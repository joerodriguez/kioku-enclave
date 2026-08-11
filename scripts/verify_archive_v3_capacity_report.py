#!/usr/bin/env python3
"""Verify the inactive ADR-0022 capacity preauthorization contract.

The accepted JSON is a deliberately restricted ASCII/safe-integer RFC-8785 profile.
The result is never deployment authority.  External request, time, replay, provenance,
and environment documents are hash-bound wrappers only; the receipt lists the independent
controls a future activation gate must still satisfy.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA = "kioku-archive-v3-capacity-evidence-v2"
POLICY_SCHEMA = "kioku-archive-v3-capacity-policy-v2"
REQUEST_SCHEMA = "kioku-archive-v3-capacity-verification-request-v1"
LEDGER_SCHEMA = "kioku-archive-v3-capacity-replay-ledger-snapshot-v1"
TIME_SCHEMA = "kioku-archive-v3-capacity-time-assertion-v1"
KEY_SCHEMA = "kioku-pinned-p256-public-key-metadata-v1"
RECEIPT_SCHEMA = "kioku-archive-v3-capacity-preauthorization-receipt-v2"

MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_DIGEST_BYTES = 128
MAX_SIGNATURE_B64_BYTES = 256
MAX_PEM_BYTES = 1024
MAX_OPENSSL_BYTES = 32 * 1024 * 1024
MAX_DEPTH = 32
MAX_INT = 2**53 - 1
CAPACITY_BYTES = 32 * 1024**3
WRITE_LIVE_DATABASE_BYTES = (1024**3, CAPACITY_BYTES)
MAX_EVIDENCE_AGE_SECONDS = 7 * 24 * 60 * 60
MAX_FUTURE_SKEW_SECONDS = 300
MAX_VALIDITY_SECONDS = 24 * 60 * 60
MIN_ACTIVE_USERS = 8
MIN_SAMPLE_COUNT = 100
MAX_ROOT_BYTES = 1024 * 1024
MAX_WITNESS_BYTES = 64 * 1024
REQUIRED_CACHE_DEFINITION = "empty-page-cache,warmed-process-model,128mib-user-v1"
REQUIRED_MEDIA_MIX = "bounded-audio-screenshot-reference-size-network-v1"
REQUIRED_LATENCY_PROFILE = "gcs-witness-kms-bigtable-latency-throttle-error-v1"
REQUIRED_PERCENTILE_WINDOW = "complete-steady-state-and-fault-window-v1"
REQUIRED_COST_MODEL = "published-on-demand-excludes-raw-vertex-bigtable-demonstrated-users-v1"
REQUIRED_VM_SHAPE = "c3d-standard-8"
REQUIRED_VM_MEMORY_BYTES = 32 * 1024**3
REQUIRED_ARCHIVE_REGION = "us-central1"
REQUIRED_WITNESS_REGION = "us-central1"
REQUIRED_SQLITE_VERSION = "3.45.3"
HEX = re.compile(r"^[a-f0-9]{64}$")
UUID = re.compile(r"^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$")
NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
IMAGE = re.compile(r"^sha256:[a-f0-9]{64}$")


class VerificationError(ValueError):
    pass


WORKLOAD_SPECS = {
    "workload-480h-year-3y-32gib": 480,
    "workload-960h-year-3y-32gib": 960,
    "workload-1200h-year-3y-32gib": 1200,
}
WORKLOADS = tuple(WORKLOAD_SPECS)
FAULTS = (
    "gcs-latency", "gcs-throttle", "gcs-error", "witness-latency", "witness-throttle",
    "witness-error", "kms-latency", "kms-throttle", "kms-error", "bigtable-latency",
    "bigtable-throttle", "bigtable-error", "object-tamper", "page-tamper", "rollback",
    "truncation", "deletion", "orphan-gc", "vm-restart", "lease-rebalance", "cold-cache-churn",
)
TESTS = (
    "scale-two-second-screen-ratio", "scale-continuous-ingest-workers", "scale-hot-user-writes",
    "scale-export", "scale-bounded-media-classes", "scale-hybrid-query-mix-70-20-10",
    "scale-conversion-vm-network", "crypto-unique-subkeys", "crypto-cross-scope-substitution",
    "crypto-tamper-merkle", "crypto-checkpoint-reorder-duplicate-truncation",
    "crypto-missing-page-node-wal-truncation", "crypto-stale-gcs-root",
    "crypto-key-rotation-envelope-deletion", "recovery-crash-every-write-cas",
    "recovery-lost-success-duplicate-retry", "recovery-candidate-orphan", "recovery-cas-fence",
    "recovery-wal-mismatch", "recovery-compaction-race", "recovery-vfs-conformance",
    "recovery-old-format-refusal", "sqlite-schema-epoch-migration", "sqlite-foreign-key-rollback",
    "sqlite-fts-integrity", "sqlite-vector-integrity", "sqlite-ann-watermark-sidecar",
    "sqlite-domain-records", "sqlite-export-parity", "concurrency-cross-user-progress",
    "concurrency-same-user-ordering", "concurrency-lease-fencing", "concurrency-forwarding-auth",
    "concurrency-pinned-root-replica", "lifecycle-prefix-rules",
    "lifecycle-generations-soft-delete", "deletion-media-intent", "deletion-tombstone-race",
    "deletion-restart-zero-inventory", "deletion-retained-root", "deletion-identity-reuse",
)
SCENARIOS = FAULTS + TESTS
INVARIANTS = (
    "integrity_check", "fts_integrity", "vector_cardinality", "logical_export_matches_legacy",
    "every_crash_recovers_witnessed_root", "no_deleted_archive_load_or_recreate",
    "plaintext_cache_configurable_downward", "overload_backpressures",
    "conversion_abort_preserves_legacy_authority", "conversion_reads_pin_old_generation",
    "conversion_clients_spool_retry", "published_on_demand_cost_model",
    "cost_excludes_raw_media_and_inference", "bigtable_cost_uses_demonstrated_users",
    "soft_delete_configuration_asserted", "legacy_generations_removed_before_erasure",
    "deletion_idempotent", "zero_inventory",
)
ARTIFACTS = (
    "release_manifest", "provenance", "sbom", "fixture_manifest", "test_plan", "test_config",
    "environment_attestation",
)
ENVIRONMENT_KEYS = {"provider", "project_id", "environment", "vm_shape", "vm_memory_bytes", "archive_backend", "archive_region", "witness_backend", "witness_region", "sqlite_version", "extensions", "cache_definition", "active_users", "request_media_mix", "latency_profile", "cost_model", "sample_count", "percentile_window", "query_mode", "provider_recovery_mode", "provider_recovery_deadline_ms"}
ACTIVATION_BLOCKERS = (
    "authenticated_rollback_protected_challenge_issuance",
    "transactional_create_if_absent_replay_consumption",
    "authenticated_trusted_time",
    "cryptographic_release_provenance_verification",
    "cryptographic_environment_attestation_verification",
    "independent_measurement_authenticity",
)

# id, operator, baseline, unit, scenario, media class, query class, slice, percentile
# Strict ADR inequalities are encoded as the greatest accepted integer below the boundary.
METRICS = (
    ("zero_rpo_acknowledged_commits", "eq", 0, "count", "recovery-crash-every-write-cas", "none", "none", "all", "exact"),
    ("p95_cold_point_read_bytes", "lte", 64 * 1024**2, "bytes", "cold-cache-churn", "none", "point", "100_result", "p95"),
    ("p95_cold_time_bounded_read_bytes", "lte", 64 * 1024**2, "bytes", "cold-cache-churn", "none", "time_bounded", "recent_24h_100", "p95"),
    ("per_user_plaintext_cache_bytes", "lte", 128 * 1024**2, "bytes", "cold-cache-churn", "none", "none", "all", "maximum"),
    ("storage_model_rss_ppm_of_vm_memory", "lte", 699999, "parts_per_million", "scale-continuous-ingest-workers", "mixed", "none", "all", "maximum"),
    ("capture_audio_post_body_p95_ms", "lte", 2000, "milliseconds", "scale-bounded-media-classes", "audio", "none", "all", "p95"),
    ("capture_audio_post_body_p99_ms", "lte", 5000, "milliseconds", "scale-bounded-media-classes", "audio", "none", "all", "p99"),
    ("capture_screenshot_post_body_p95_ms", "lte", 2000, "milliseconds", "scale-bounded-media-classes", "screenshot", "none", "all", "p95"),
    ("capture_screenshot_post_body_p99_ms", "lte", 5000, "milliseconds", "scale-bounded-media-classes", "screenshot", "none", "all", "p99"),
    ("reference_envelope_post_body_p95_ms", "lte", 2000, "milliseconds", "scale-two-second-screen-ratio", "reference", "none", "all", "p95"),
    ("reference_envelope_post_body_p99_ms", "lte", 5000, "milliseconds", "scale-two-second-screen-ratio", "reference", "none", "all", "p99"),
    ("reference_flush_ms", "lte", 10000, "milliseconds", "scale-two-second-screen-ratio", "reference", "none", "all", "maximum"),
    ("reference_observation_to_durable_p95_ms", "lte", 12000, "milliseconds", "scale-two-second-screen-ratio", "reference", "none", "all", "p95"),
    ("canonical_media_flush_ms", "eq", 0, "milliseconds", "scale-bounded-media-classes", "canonical", "none", "all", "exact"),
    ("explicit_user_stop_flush_ms", "eq", 0, "milliseconds", "scale-bounded-media-classes", "user_stop", "none", "all", "exact"),
    ("recent_time_query_p95_ms", "lte", 3000, "milliseconds", "cold-cache-churn", "none", "time_bounded", "recent_24h_100", "p95"),
    ("recent_fts_query_p95_ms", "lte", 3000, "milliseconds", "cold-cache-churn", "none", "fts", "recent_24h_100", "p95"),
    ("recent_exact_knn_query_p95_ms", "lte", 3000, "milliseconds", "cold-cache-churn", "none", "exact_knn", "recent_24h_100", "p95"),
    ("all_time_hybrid_32gib_p95_ms", "lte", 10000, "milliseconds", "scale-hybrid-query-mix-70-20-10", "none", "hybrid_70_20_10", "all_time_100", "p95"),
    ("cross_user_lock_wait_p95_ms", "lte", 99, "milliseconds", "concurrency-cross-user-progress", "none", "none", "gcs_kms_30s_delay", "p95"),
    ("same_user_conflict_ppm", "lte", 999, "parts_per_million", "concurrency-same-user-ordering", "none", "none", "non_handoff", "aggregate"),
    ("conversion_write_fence_p95_ms", "lte", 1800000, "milliseconds", "scale-conversion-vm-network", "none", "none", "32gib_conversion", "p95"),
    ("orphan_bytes_ppm_of_live", "lte", 49999, "parts_per_million", "orphan-gc", "none", "none", "post_grace", "maximum"),
    ("orphan_collection_ms", "lte", 86400000, "milliseconds", "orphan-gc", "none", "none", "post_grace", "maximum"),
    ("legacy_noncurrent_generation_count", "lte", 3, "count", "lifecycle-generations-soft-delete", "none", "none", "legacy_indexes", "maximum"),
    ("legacy_noncurrent_age_seconds", "lte", 604800, "seconds", "lifecycle-generations-soft-delete", "none", "none", "legacy_indexes", "maximum"),
    ("raw_media_application_retention_days", "eq", 30, "days", "lifecycle-prefix-rules", "audio", "none", "application", "exact"),
    ("raw_media_bucket_hard_cap_days", "eq", 35, "days", "lifecycle-prefix-rules", "audio", "none", "bucket", "exact"),
    ("normal_ack_full_database_download_count", "eq", 0, "count", "scale-hot-user-writes", "none", "none", "normal_commit", "exact"),
    ("normal_ack_full_database_upload_count", "eq", 0, "count", "scale-hot-user-writes", "none", "none", "normal_commit", "exact"),
    ("normal_commit_durable_bytes_growth_per_gib", "eq", 0, "bytes_per_gib", "scale-hot-user-writes", "none", "none", "normal_commit", "exact"),
    ("normal_commit_object_operations_growth_per_gib", "eq", 0, "operations_per_gib", "scale-hot-user-writes", "none", "none", "normal_commit", "exact"),
    ("fts_commit_durable_bytes_growth_per_gib", "eq", 0, "bytes_per_gib", "scale-hot-user-writes", "none", "fts", "fts_commit", "exact"),
    ("fts_commit_object_operations_growth_per_gib", "eq", 0, "operations_per_gib", "scale-hot-user-writes", "none", "fts", "fts_commit", "exact"),
    ("monthly_cost_microusd", "lte", 10000000, "microusd", "scale-continuous-ingest-workers", "mixed", "none", "100h_month_on_demand", "aggregate"),
    ("tombstone_revocation_p95_ms", "lte", 5000, "milliseconds", "deletion-tombstone-race", "none", "none", "all", "p95"),
    ("key_envelope_erasure_p95_ms", "lte", 60000, "milliseconds", "deletion-restart-zero-inventory", "none", "none", "central_registry", "p95"),
    ("physical_deletion_post_recovery_ms", "lte", 86400000, "milliseconds", "deletion-restart-zero-inventory", "none", "none", "32gib_3y", "maximum"),
    ("root_object_growth_bytes_per_gib", "eq", 0, "bytes_per_gib", "scale-hot-user-writes", "none", "none", "root", "exact"),
    ("witness_record_growth_bytes_per_gib", "eq", 0, "bytes_per_gib", "scale-hot-user-writes", "none", "none", "witness", "exact"),
    ("root_max_bytes", "lte", MAX_ROOT_BYTES, "bytes", "scale-hot-user-writes", "none", "none", "root", "maximum"),
    ("witness_max_bytes", "lte", MAX_WITNESS_BYTES, "bytes", "scale-hot-user-writes", "none", "none", "witness", "maximum"),
)
METRIC_MAP = {row[0]: row for row in METRICS}

# Every scenario is exercised for every workload.  Scenarios with quantitative metrics
# are further split by the metric's exact media/query/slice/percentile dimensions.
_metric_case_dimensions = tuple(dict.fromkeys(row[4:9] for row in METRICS))
CASE_DIMENSIONS = _metric_case_dimensions + tuple(
    (scenario, "none", "none", "all", "exact")
    for scenario in SCENARIOS
    if not any(dimension[0] == scenario for dimension in _metric_case_dimensions)
)


def reject_constant(value: str) -> None:
    raise VerificationError(f"non-finite JSON number: {value}")


def no_duplicates(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise VerificationError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def string(value: Any, where: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value or not value.isascii() or (pattern and not pattern.fullmatch(value)):
        raise VerificationError(f"invalid {where}")
    return value


def integer(value: Any, where: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum or value > MAX_INT:
        raise VerificationError(f"invalid {where}")
    return value


def exact(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise VerificationError(f"{where} must contain exactly {sorted(keys)}")
    return value


def list_of(value: Any, where: str, maximum: int = 256) -> list[Any]:
    if not isinstance(value, list) or len(value) > maximum:
        raise VerificationError(f"invalid {where}")
    return value


def checked_depth(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise VerificationError("JSON exceeds nesting limit")
    if isinstance(value, str):
        string(value, "JSON string")
    elif type(value) is int:
        integer(value, "JSON integer", -MAX_INT)
    elif value is None or type(value) is bool:
        return
    elif isinstance(value, list):
        for item in value:
            checked_depth(item, depth + 1)
    elif isinstance(value, dict):
        for key, item in value.items():
            string(key, "JSON key")
            checked_depth(item, depth + 1)
    else:
        raise VerificationError("restricted JCS profile forbids floats and non-JSON values")


def read_regular(path: Path, maximum: int, where: str) -> bytes:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise VerificationError("platform lacks no-follow file opening")
    parts = path.parts
    if any(part in {".", ".."} for part in parts):
        raise VerificationError(f"unsafe {where} path")
    nofollow = os.O_NOFOLLOW
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | nofollow
    descriptor = None
    directory = None
    try:
        directory = os.open("/" if path.is_absolute() else ".", directory_flags)
        components = parts[1:] if path.is_absolute() else parts
        if not components:
            raise VerificationError(f"invalid {where} path")
        for component in components[:-1]:
            next_directory = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = next_directory
        descriptor = os.open(components[-1], os.O_RDONLY | nofollow, dir_fd=directory)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
                raise VerificationError(f"invalid {where} file")
            data = os.read(descriptor, maximum + 1)
            if len(data) != info.st_size or len(data) > maximum:
                raise VerificationError(f"invalid {where} size")
            return data
        finally:
            os.close(descriptor)
            descriptor = None
    except OSError as error:
        raise VerificationError(f"cannot read {where}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def load_json(path: Path) -> tuple[Any, bytes]:
    raw = read_regular(path, MAX_JSON_BYTES, str(path))
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates, parse_constant=reject_constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"cannot parse {path}: {error}") from error
    checked_depth(value)
    return value, raw


def canonical(value: Any) -> bytes:
    checked_depth(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("ascii")
    except (TypeError, UnicodeError, ValueError) as error:
        raise VerificationError("cannot canonicalize restricted JCS value") from error


def hash_field(value: Any, where: str) -> str:
    return string(value, where, HEX)


def iso_time(value: Any, where: str) -> datetime:
    raw = string(value, where)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", raw):
        raise VerificationError(f"invalid {where}")
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise VerificationError(f"invalid {where}") from error


def exact_string_list(value: Any, required: tuple[str, ...], where: str) -> None:
    items = [string(item, where) for item in list_of(value, where, len(required))]
    if tuple(items) != required or len(items) != len(set(items)):
        raise VerificationError(f"wrong {where}")


def validate_environment(value: Any, where: str) -> dict[str, Any]:
    environment = exact(value, ENVIRONMENT_KEYS, where)
    for key in ENVIRONMENT_KEYS - {"extensions", "vm_memory_bytes", "active_users", "sample_count", "provider_recovery_deadline_ms"}:
        string(environment[key], f"{where}.{key}")
    if environment["provider"] != "gcp" or environment["archive_backend"] != "gcs" or environment["witness_backend"] != "firestore":
        raise VerificationError("wrong provider/backend contract")
    if (environment["vm_shape"] != REQUIRED_VM_SHAPE or
            integer(environment["vm_memory_bytes"], "VM memory bytes", 1) != REQUIRED_VM_MEMORY_BYTES or
            environment["archive_region"] != REQUIRED_ARCHIVE_REGION or
            environment["witness_region"] != REQUIRED_WITNESS_REGION or
            environment["sqlite_version"] != REQUIRED_SQLITE_VERSION):
        raise VerificationError("wrong VM, region, or SQLite contract")
    if (environment["cache_definition"] != REQUIRED_CACHE_DEFINITION or
            environment["request_media_mix"] != REQUIRED_MEDIA_MIX or
            environment["latency_profile"] != REQUIRED_LATENCY_PROFILE or
            environment["cost_model"] != REQUIRED_COST_MODEL or
            environment["percentile_window"] != REQUIRED_PERCENTILE_WINDOW):
        raise VerificationError("wrong cache/media/latency/window contract")
    if integer(environment["active_users"], "active users", MIN_ACTIVE_USERS) < MIN_ACTIVE_USERS:
        raise VerificationError("insufficient active-user load")
    if integer(environment["sample_count"], "sample count", MIN_SAMPLE_COUNT) < MIN_SAMPLE_COUNT:
        raise VerificationError("insufficient percentile sample count")
    extensions = [string(item, "extension") for item in list_of(environment["extensions"], "extensions", 16)]
    if tuple(extensions) != ("fts5", "sqlite-vec"):
        raise VerificationError("wrong SQLite extensions")
    if environment["query_mode"] not in {"exact_knn", "ann"}:
        raise VerificationError("invalid vector query mode")
    deadline = integer(environment["provider_recovery_deadline_ms"], "provider recovery deadline")
    if environment["provider_recovery_mode"] == "disabled" and deadline != 0:
        raise VerificationError("disabled recovery must have zero deadline")
    if environment["provider_recovery_mode"] == "retained" and deadline == 0:
        raise VerificationError("retained recovery requires disclosed deadline")
    if environment["provider_recovery_mode"] not in {"disabled", "retained"}:
        raise VerificationError("invalid provider recovery mode")
    return environment


def validate_metrics_policy(value: Any) -> dict[str, dict[str, Any]]:
    rows = list_of(value, "policy metrics", len(METRICS))
    if len(rows) != len(METRICS):
        raise VerificationError("wrong metric count")
    result = {}
    for row in rows:
        row = exact(row, {"id", "operator", "value", "unit", "scenario_id", "media_class", "query_class", "slice", "percentile"}, "policy metric")
        ident = string(row["id"], "metric id")
        base = METRIC_MAP.get(ident)
        if base is None or ident in result or tuple(row[key] for key in ("operator", "unit", "scenario_id", "media_class", "query_class", "slice", "percentile")) != (base[1], base[3], base[4], base[5], base[6], base[7], base[8]):
            raise VerificationError("metric identity/context changed")
        observed = integer(row["value"], "metric policy value")
        if base[1] == "lte" and observed > base[2]:
            raise VerificationError("metric relaxed")
        if base[1] == "gte" and observed < base[2]:
            raise VerificationError("metric relaxed")
        if base[1] == "eq" and observed != base[2]:
            raise VerificationError("equality metric changed")
        result[ident] = row
    if set(result) != set(METRIC_MAP):
        raise VerificationError("metric matrix incomplete")
    return result


def validate_policy(value: Any) -> dict[str, Any]:
    policy = exact(value, {"schema", "contract_id", "capacity_bytes", "write_live_database_bytes", "workload_ids", "fault_ids", "test_ids", "invariant_ids", "metrics", "required_environment", "fixture_manifest_sha256", "test_plan_sha256", "test_config_sha256", "max_evidence_age_seconds", "max_future_skew_seconds", "max_validity_seconds", "trusted_signers", "allowed_time_sources", "openssl_sha256"}, "policy")
    if policy["schema"] != POLICY_SCHEMA or policy["contract_id"] != "adr0022-phase1-32gib-v2":
        raise VerificationError("wrong policy contract")
    if integer(policy["capacity_bytes"], "capacity bytes") != CAPACITY_BYTES:
        raise VerificationError("capacity must be exact 32 GiB")
    write_sizes = tuple(integer(item, "write live database bytes", 1) for item in list_of(policy["write_live_database_bytes"], "write live database bytes", len(WRITE_LIVE_DATABASE_BYTES)))
    if write_sizes != WRITE_LIVE_DATABASE_BYTES:
        raise VerificationError("write live-size trace changed")
    exact_string_list(policy["workload_ids"], WORKLOADS, "workload ids")
    exact_string_list(policy["fault_ids"], FAULTS, "fault ids")
    exact_string_list(policy["test_ids"], TESTS, "test ids")
    exact_string_list(policy["invariant_ids"], INVARIANTS, "invariant ids")
    validate_metrics_policy(policy["metrics"])
    validate_environment(policy["required_environment"], "policy required environment")
    for field in ("fixture_manifest_sha256", "test_plan_sha256", "test_config_sha256"):
        hash_field(policy[field], f"policy {field}")
    age = integer(policy["max_evidence_age_seconds"], "max evidence age", 1)
    skew = integer(policy["max_future_skew_seconds"], "max future skew")
    validity = integer(policy["max_validity_seconds"], "max validity", 1)
    if age > MAX_EVIDENCE_AGE_SECONDS or skew > MAX_FUTURE_SKEW_SECONDS or validity > MAX_VALIDITY_SECONDS:
        raise VerificationError("freshness policy relaxed")
    signers = list_of(policy["trusted_signers"], "trusted signers", 16)
    if not signers:
        raise VerificationError("no trusted signer")
    seen = set()
    for signer in signers:
        signer = exact(signer, {"kms_key_version", "public_key_spki_der_sha256", "metadata_raw_sha256", "metadata_canonical_sha256", "evaluator_id", "evaluator_organization", "evaluator_tool_sha256", "evaluator_container_sha256", "rotation_status"}, "trusted signer")
        key_version = string(signer["kms_key_version"], "KMS key version")
        if key_version in seen:
            raise VerificationError("duplicate signer")
        seen.add(key_version)
        for key in ("public_key_spki_der_sha256", "metadata_raw_sha256", "metadata_canonical_sha256", "evaluator_tool_sha256", "evaluator_container_sha256"):
            hash_field(signer[key], key)
        string(signer["evaluator_id"], "evaluator id")
        string(signer["evaluator_organization"], "evaluator organization")
        if signer["rotation_status"] != "active":
            raise VerificationError("inactive signer")
    sources = [string(item, "allowed time source") for item in list_of(policy["allowed_time_sources"], "allowed time sources", 16)]
    if not sources or len(sources) != len(set(sources)):
        raise VerificationError("invalid time-source allowlist")
    hash_field(policy["openssl_sha256"], "openssl hash")
    return policy


def validate_binding(value: Any, where: str) -> dict[str, Any]:
    binding = exact(value, {"raw_sha256", "canonical_sha256", "subject_sha256"}, where)
    for key in binding:
        hash_field(binding[key], f"{where}.{key}")
    return binding


def validate_request(value: Any, policy: dict[str, Any]) -> dict[str, Any]:
    request = exact(value, {"schema", "request_id", "nonce", "release", "environment", "artifact_bindings"}, "verification request wrapper")
    if request["schema"] != REQUEST_SCHEMA:
        raise VerificationError("wrong request schema")
    string(request["request_id"], "request id", UUID)
    string(request["nonce"], "request nonce", NONCE)
    release = exact(request["release"], {"source_repository", "git_commit", "release_tag", "image_digest"}, "request release")
    string(release["source_repository"], "source repository")
    string(release["git_commit"], "git commit", re.compile(r"^[a-f0-9]{40}$"))
    string(release["release_tag"], "release tag")
    string(release["image_digest"], "image digest", IMAGE)
    environment = validate_environment(request["environment"], "request environment")
    if environment != policy["required_environment"]:
        raise VerificationError("request environment is not exact policy environment")
    bindings = exact(request["artifact_bindings"], set(ARTIFACTS), "artifact bindings")
    for name in ARTIFACTS:
        validate_binding(bindings[name], f"artifact binding {name}")
    for name, policy_field in (("fixture_manifest", "fixture_manifest_sha256"),
                               ("test_plan", "test_plan_sha256"),
                               ("test_config", "test_config_sha256")):
        if bindings[name]["raw_sha256"] != policy[policy_field]:
            raise VerificationError(f"request {name} is not policy-pinned")
    return request


def validate_ledger(value: Any) -> dict[str, Any]:
    ledger = exact(value, {"schema", "sequence", "previous_snapshot_sha256", "consumed_nonces", "consumed_request_sha256", "consumed_report_sha256"}, "untrusted replay-ledger snapshot")
    if ledger["schema"] != LEDGER_SCHEMA:
        raise VerificationError("wrong replay-ledger schema")
    integer(ledger["sequence"], "ledger sequence")
    hash_field(ledger["previous_snapshot_sha256"], "previous ledger snapshot")
    for key in ("consumed_nonces", "consumed_request_sha256", "consumed_report_sha256"):
        values = list_of(ledger[key], key, 4096)
        if len(values) != len(set(values)):
            raise VerificationError(f"duplicate {key}")
        pattern = NONCE if key == "consumed_nonces" else HEX
        for item in values:
            string(item, key, pattern)
    return ledger


def validate_time_assertion(value: Any, policy: dict[str, Any], local_now: datetime) -> dict[str, Any]:
    assertion = exact(value, {"schema", "source", "issued_at", "expires_at", "asserted_now", "wrapper_sha256"}, "unauthenticated time assertion wrapper")
    if assertion["schema"] != TIME_SCHEMA or string(assertion["source"], "time source") not in policy["allowed_time_sources"]:
        raise VerificationError("unallowed time wrapper source")
    issued = iso_time(assertion["issued_at"], "time assertion issued")
    expires = iso_time(assertion["expires_at"], "time assertion expires")
    asserted = iso_time(assertion["asserted_now"], "asserted now")
    hash_field(assertion["wrapper_sha256"], "time wrapper hash")
    validity = timedelta(seconds=policy["max_validity_seconds"])
    skew = timedelta(seconds=policy["max_future_skew_seconds"])
    if expires <= issued or expires - issued > validity or asserted < issued or asserted > expires or abs(local_now - asserted) > skew:
        raise VerificationError("invalid time wrapper window")
    return assertion


def validate_artifacts(request: dict[str, Any], paths: dict[str, Path]) -> None:
    expected_subject = {"release": request["release"], "environment": request["environment"]}
    for name in ARTIFACTS:
        value, raw = load_json(paths[name])
        wrapper = exact(value, {"schema", "subject", "payload_sha256"}, f"{name} wrapper")
        if wrapper["schema"] != f"kioku-capacity-{name.replace('_', '-')}-wrapper-v1":
            raise VerificationError(f"wrong {name} wrapper schema")
        hash_field(wrapper["payload_sha256"], f"{name} payload hash")
        if wrapper["subject"] != expected_subject:
            raise VerificationError(f"{name} subject mismatch")
        binding = request["artifact_bindings"][name]
        if sha256(raw) != binding["raw_sha256"] or sha256(canonical(value)) != binding["canonical_sha256"] or sha256(canonical(wrapper["subject"])) != binding["subject_sha256"]:
            raise VerificationError(f"{name} wrapper hash mismatch")


def validate_workloads(value: Any, fixture_hash: str) -> None:
    rows = list_of(value, "workloads", len(WORKLOADS))
    if len(rows) != len(WORKLOADS):
        raise VerificationError("wrong workload count")
    seen = set()
    for row in rows:
        row = exact(row, {"id", "recording_hours_per_year", "years", "logical_capacity_bytes", "screen_interval_seconds", "canonical_screen_ratio_ppm", "reference_screen_ratio_ppm", "fixture_manifest_sha256", "artifact_sha256"}, "workload")
        ident = string(row["id"], "workload id")
        if ident in seen or ident not in WORKLOAD_SPECS:
            raise VerificationError("duplicate or unknown workload")
        seen.add(ident)
        if integer(row["recording_hours_per_year"], "recording hours", 1) != WORKLOAD_SPECS[ident] or integer(row["years"], "years", 1) != 3 or integer(row["logical_capacity_bytes"], "capacity", 1) != CAPACITY_BYTES or integer(row["screen_interval_seconds"], "screen interval", 1) != 2 or integer(row["canonical_screen_ratio_ppm"], "canonical ratio") != 100000 or integer(row["reference_screen_ratio_ppm"], "reference ratio") != 900000:
            raise VerificationError("workload geometry mismatch")
        if hash_field(row["fixture_manifest_sha256"], "fixture manifest hash") != fixture_hash:
            raise VerificationError("workload fixture mismatch")
        hash_field(row["artifact_sha256"], "workload artifact")
    if seen != set(WORKLOADS):
        raise VerificationError("workload matrix incomplete")


RESULT_BINDING_KEYS = {
    "workload_id", "database_bytes", "years", "fixture_manifest_sha256",
    "test_plan_sha256", "test_config_sha256", "environment_sha256",
    "environment_attestation_sha256", "cache_definition", "active_users",
    "request_media_mix", "latency_profile", "cost_model", "sample_count", "percentile_window",
}


def validate_result_binding(row: dict[str, Any], request: dict[str, Any], where: str) -> str:
    workload = string(row["workload_id"], f"{where} workload")
    if workload not in WORKLOAD_SPECS or integer(row["database_bytes"], f"{where} database bytes", 1) != CAPACITY_BYTES or integer(row["years"], f"{where} years", 1) != 3:
        raise VerificationError(f"{where} does not exercise exact 32-GiB/three-year workload")
    expected = request["artifact_bindings"]
    if hash_field(row["fixture_manifest_sha256"], f"{where} fixture") != expected["fixture_manifest"]["raw_sha256"] or hash_field(row["test_plan_sha256"], f"{where} test plan") != expected["test_plan"]["raw_sha256"] or hash_field(row["test_config_sha256"], f"{where} test config") != expected["test_config"]["raw_sha256"]:
        raise VerificationError(f"{where} artifact binding mismatch")
    environment = request["environment"]
    if (hash_field(row["environment_sha256"], f"{where} environment") != sha256(canonical(environment)) or
            hash_field(row["environment_attestation_sha256"], f"{where} environment attestation") != expected["environment_attestation"]["raw_sha256"] or
            row["cache_definition"] != environment["cache_definition"] or
            integer(row["active_users"], f"{where} active users", MIN_ACTIVE_USERS) != environment["active_users"] or
            row["request_media_mix"] != environment["request_media_mix"] or
            row["latency_profile"] != environment["latency_profile"] or
            row["cost_model"] != environment["cost_model"] or
            integer(row["sample_count"], f"{where} sample count", MIN_SAMPLE_COUNT) != environment["sample_count"] or
            row["percentile_window"] != environment["percentile_window"]):
        raise VerificationError(f"{where} run-dimension binding mismatch")
    return workload


def validate_cases(value: Any, request: dict[str, Any]) -> None:
    expected_samples = request["environment"]["sample_count"]
    expected_pairs = {(workload, *dimension) for workload in WORKLOADS for dimension in CASE_DIMENSIONS}
    rows = list_of(value, "case results", len(expected_pairs))
    if len(rows) != len(expected_pairs):
        raise VerificationError("wrong case count")
    seen = set()
    for row in rows:
        row = exact(row, RESULT_BINDING_KEYS | {"scenario_id", "kind", "status", "media_class", "query_class", "slice", "percentile", "assertion_count", "failed_assertions", "injected_count", "recovered_count", "artifact_sha256", "measurement_sha256"}, "case result")
        workload = validate_result_binding(row, request, "case result")
        ident = string(row["scenario_id"], "case scenario")
        kind = "fault" if ident in FAULTS else "test" if ident in TESTS else None
        dimensions = tuple(string(row[key], f"case {key}") for key in ("media_class", "query_class", "slice", "percentile"))
        pair = (workload, ident, *dimensions)
        if pair in seen or kind is None or row["kind"] != kind or row["status"] != "passed":
            raise VerificationError("invalid case result")
        seen.add(pair)
        if integer(row["assertion_count"], "case assertion count", 1) < 1 or integer(row["failed_assertions"], "failed assertions") != 0:
            raise VerificationError("case measurement counters invalid")
        expected_injections = expected_samples if kind == "fault" else 0
        if integer(row["injected_count"], "injected count") != expected_injections or integer(row["recovered_count"], "recovered count") != expected_injections:
            raise VerificationError("fault/recovery counters contradict case kind")
        hash_field(row["artifact_sha256"], "case artifact")
        hash_field(row["measurement_sha256"], "case measurement")
    if seen != expected_pairs:
        raise VerificationError("case matrix incomplete")


def validate_measurements(value: Any, policy: dict[str, Any], request: dict[str, Any]) -> dict[tuple[str, str], int]:
    rules = validate_metrics_policy(policy["metrics"])
    expected_pairs = {(workload, metric) for workload in WORKLOADS for metric in METRIC_MAP}
    rows = list_of(value, "measurements", len(expected_pairs))
    if len(rows) != len(expected_pairs):
        raise VerificationError("wrong measurement count")
    seen = set()
    observations = {}
    for row in rows:
        row = exact(row, RESULT_BINDING_KEYS | {"id", "operator", "limit", "unit", "observed", "scenario_id", "media_class", "query_class", "slice", "percentile", "artifact_sha256"}, "measurement")
        workload = validate_result_binding(row, request, "measurement")
        ident = string(row["id"], "measurement id")
        rule = rules.get(ident)
        pair = (workload, ident)
        if pair in seen or rule is None:
            raise VerificationError("duplicate or unknown measurement")
        seen.add(pair)
        for key in ("operator", "unit", "scenario_id", "media_class", "query_class", "slice", "percentile"):
            if row[key] != rule[key]:
                raise VerificationError("measurement context substitution")
        limit = integer(row["limit"], "measurement limit")
        observed = integer(row["observed"], "measurement observed")
        if limit != rule["value"]:
            raise VerificationError("measurement binding mismatch")
        hash_field(row["artifact_sha256"], "measurement artifact")
        if not ((row["operator"] == "lte" and observed <= limit) or (row["operator"] == "gte" and observed >= limit) or (row["operator"] == "eq" and observed == limit)):
            raise VerificationError("threshold failure")
        observations[pair] = observed
    if seen != expected_pairs:
        raise VerificationError("measurement matrix incomplete")
    return observations


def nearest_rank(values: list[int], percentile: int) -> int:
    ordered = sorted(values)
    return ordered[(percentile * len(ordered) + 99) // 100 - 1]


def validate_write_samples(samples: Any, summaries: Any, request: dict[str, Any]) -> dict[tuple[str, str], int]:
    expected_count = request["environment"]["sample_count"]
    slices = ("normal", "fts", "vector")
    expected_traces = {(workload, slice_id, live_size) for workload in WORKLOADS for slice_id in slices for live_size in WRITE_LIVE_DATABASE_BYTES}
    rows = list_of(samples, "durable-write traces", len(expected_traces))
    if len(rows) != len(expected_traces):
        raise VerificationError("durable-write trace count mismatch")
    seen_traces = set()
    samples_by_trace: dict[tuple[str, str, int], dict[str, tuple[int, int, int]]] = {}
    for row in rows:
        row = exact(row, RESULT_BINDING_KEYS | {"live_database_bytes", "scenario_id", "media_class", "query_class", "slice", "percentile", "samples", "artifact_sha256"}, "durable-write trace")
        workload = validate_result_binding(row, request, "durable-write trace")
        slice_id = string(row["slice"], "write trace slice")
        live_size = integer(row["live_database_bytes"], "live database bytes", 1)
        key = (workload, slice_id, live_size)
        query_class = slice_id if slice_id in {"fts", "vector"} else "none"
        if (key in seen_traces or key not in expected_traces or
                (row["scenario_id"], row["media_class"], row["query_class"], row["percentile"]) !=
                ("scale-hot-user-writes", "none", query_class, "raw_samples")):
            raise VerificationError("duplicate or invalid write trace")
        seen_traces.add(key)
        trace_samples = list_of(row["samples"], "durable-write samples", expected_count)
        if len(trace_samples) != expected_count:
            raise VerificationError("durable-write sample count mismatch")
        by_id = {}
        for sample in trace_samples:
            sample = exact(sample, {"sample_id", "changed_sqlite_bytes", "durable_bytes", "object_operations", "artifact_sha256"}, "durable-write sample")
            sample_id = string(sample["sample_id"], "write sample id")
            if sample_id in by_id:
                raise VerificationError("duplicate write sample")
            changed = integer(sample["changed_sqlite_bytes"], "changed bytes", 1)
            durable = integer(sample["durable_bytes"], "durable bytes", 1)
            operations = integer(sample["object_operations"], "object operations", 1)
            if durable < changed or durable > 4 * changed + 2 * 1024**2:
                raise VerificationError("durable-write physical/formula failure")
            hash_field(sample["artifact_sha256"], "write sample artifact")
            by_id[sample_id] = (changed, durable, operations)
        samples_by_trace[key] = by_id
        hash_field(row["artifact_sha256"], "write trace artifact")
    if seen_traces != expected_traces:
        raise VerificationError("durable-write trace matrix incomplete")

    for workload in WORKLOADS:
        for slice_id in slices:
            small = samples_by_trace[(workload, slice_id, WRITE_LIVE_DATABASE_BYTES[0])]
            large = samples_by_trace[(workload, slice_id, WRITE_LIVE_DATABASE_BYTES[1])]
            if set(small) != set(large) or any(small[sample_id][0] != large[sample_id][0] for sample_id in small):
                raise VerificationError("live-size traces must pair fixed changed-byte samples")

    summary_rows = list_of(summaries, "write summaries", len(expected_traces))
    if len(summary_rows) != len(expected_traces):
        raise VerificationError("missing write summaries")
    seen_summaries = set()
    for row in summary_rows:
        row = exact(row, RESULT_BINDING_KEYS | {"live_database_bytes", "scenario_id", "media_class", "query_class", "slice", "percentile", "p95_durable_bytes", "p99_durable_bytes", "worst_durable_bytes", "p95_object_operations", "p99_object_operations", "worst_object_operations", "artifact_sha256"}, "write summary")
        workload = validate_result_binding(row, request, "write summary")
        slice_id = string(row["slice"], "write slice")
        live_size = integer(row["live_database_bytes"], "summary live database bytes", 1)
        key = (workload, slice_id, live_size)
        query_class = slice_id if slice_id in {"fts", "vector"} else "none"
        if (key in seen_summaries or key not in expected_traces or
                (row["scenario_id"], row["media_class"], row["query_class"], row["percentile"]) !=
                ("scale-hot-user-writes", "none", query_class, "p95_p99_worst")):
            raise VerificationError("invalid write summary slice")
        seen_summaries.add(key)
        values = list(samples_by_trace[key].values())
        durable_values = [item[1] for item in values]
        operation_values = [item[2] for item in values]
        durable_summary = tuple(integer(row[field], field) for field in ("p95_durable_bytes", "p99_durable_bytes", "worst_durable_bytes"))
        operation_summary = tuple(integer(row[field], field) for field in ("p95_object_operations", "p99_object_operations", "worst_object_operations"))
        if durable_summary != (nearest_rank(durable_values, 95), nearest_rank(durable_values, 99), max(durable_values)) or operation_summary != (nearest_rank(operation_values, 95), nearest_rank(operation_values, 99), max(operation_values)):
            raise VerificationError("invalid write summary")
        hash_field(row["artifact_sha256"], "write summary artifact")
    if seen_summaries != expected_traces:
        raise VerificationError("write summary matrix incomplete")

    span_gib = (WRITE_LIVE_DATABASE_BYTES[1] - WRITE_LIVE_DATABASE_BYTES[0]) // 1024**3
    derived = {}
    for workload in WORKLOADS:
        for slice_id, durable_metric, operation_metric in (
                ("normal", "normal_commit_durable_bytes_growth_per_gib", "normal_commit_object_operations_growth_per_gib"),
                ("fts", "fts_commit_durable_bytes_growth_per_gib", "fts_commit_object_operations_growth_per_gib")):
            small = samples_by_trace[(workload, slice_id, WRITE_LIVE_DATABASE_BYTES[0])]
            large = samples_by_trace[(workload, slice_id, WRITE_LIVE_DATABASE_BYTES[1])]
            durable_growth = max(max(0, large[sample_id][1] - small[sample_id][1]) for sample_id in small)
            operation_growth = max(max(0, large[sample_id][2] - small[sample_id][2]) for sample_id in small)
            derived[(workload, durable_metric)] = (durable_growth + span_gib - 1) // span_gib
            derived[(workload, operation_metric)] = (operation_growth + span_gib - 1) // span_gib
    return derived


def validate_ann(value: Any, fixture_hash: str, query_mode: str, request: dict[str, Any]) -> None:
    rows = list_of(value, "ANN results", len(WORKLOADS))
    if query_mode == "exact_knn":
        if rows:
            raise VerificationError("ANN claims forbidden in exact-KNN mode")
        return
    if len(rows) != len(WORKLOADS):
        raise VerificationError("wrong ANN result count")
    seen = set()
    for row in rows:
        row = exact(row, RESULT_BINDING_KEYS | {"scenario_id", "media_class", "query_class", "slice", "percentile", "recall_at_20_ppm", "missing_ann_delta_members", "artifact_sha256"}, "ANN result")
        workload = validate_result_binding(row, request, "ANN result")
        if (workload in seen or workload not in WORKLOAD_SPECS or
                (row["scenario_id"], row["media_class"], row["query_class"], row["slice"], row["percentile"]) !=
                ("sqlite-ann-watermark-sidecar", "none", "ann", "full_fixture_recall_at_20_and_exact_delta", "aggregate") or
                integer(row["recall_at_20_ppm"], "recall@20") < 970000 or integer(row["missing_ann_delta_members"], "missing ANN members") != 0 or hash_field(row["fixture_manifest_sha256"], "ANN fixture hash") != fixture_hash):
            raise VerificationError("ANN gate failure")
        seen.add(workload)
        hash_field(row["artifact_sha256"], "ANN artifact")
    if seen != set(WORKLOADS):
        raise VerificationError("ANN fixture coverage incomplete")


def validate_transport_breakdowns(value: Any, request: dict[str, Any], observations: dict[tuple[str, str], int]) -> None:
    media_specs = {
        "audio": ("bounded_audio", "capture_audio_post_body_p95_ms", "capture_audio_post_body_p99_ms"),
        "screenshot": ("bounded_screenshot", "capture_screenshot_post_body_p95_ms", "capture_screenshot_post_body_p99_ms"),
        "reference": ("metadata_reference", "reference_envelope_post_body_p95_ms", "reference_envelope_post_body_p99_ms"),
    }
    expected = {(workload, media) for workload in WORKLOADS for media in media_specs}
    rows = list_of(value, "transport breakdowns", len(expected))
    if len(rows) != len(expected):
        raise VerificationError("wrong transport-breakdown count")
    seen = set()
    for row in rows:
        row = exact(row, RESULT_BINDING_KEYS | {"scenario_id", "media_class", "media_size_class", "network_class", "query_class", "slice", "percentile", "client_to_edge_p95_ms", "edge_to_enclave_p95_ms", "enclave_processing_p95_ms", "client_observed_p95_ms", "client_to_edge_p99_ms", "edge_to_enclave_p99_ms", "enclave_processing_p99_ms", "client_observed_p99_ms", "artifact_sha256"}, "transport breakdown")
        workload = validate_result_binding(row, request, "transport breakdown")
        media = string(row["media_class"], "transport media class")
        pair = (workload, media)
        if pair in seen or media not in media_specs:
            raise VerificationError("duplicate transport breakdown")
        seen.add(pair)
        size_class, p95_metric, p99_metric = media_specs[media]
        expected_scenario = "scale-two-second-screen-ratio" if media == "reference" else "scale-bounded-media-classes"
        if (row["media_size_class"] != size_class or row["network_class"] != "declared_bounded_network_classes" or
                (row["scenario_id"], row["query_class"], row["slice"], row["percentile"]) !=
                (expected_scenario, "none", "post_body_and_client_observed", "p95_p99")):
            raise VerificationError("transport dimension mismatch")
        p95_parts = [integer(row[key], key) for key in ("client_to_edge_p95_ms", "edge_to_enclave_p95_ms", "enclave_processing_p95_ms")]
        p99_parts = [integer(row[key], key) for key in ("client_to_edge_p99_ms", "edge_to_enclave_p99_ms", "enclave_processing_p99_ms")]
        client_p95 = integer(row["client_observed_p95_ms"], "client observed p95")
        client_p99 = integer(row["client_observed_p99_ms"], "client observed p99")
        if p95_parts[2] != observations[(workload, p95_metric)] or p99_parts[2] != observations[(workload, p99_metric)] or client_p95 < max(p95_parts) or client_p99 < max(p99_parts) or client_p95 > client_p99:
            raise VerificationError("transport breakdown contradicts server/client metrics")
        hash_field(row["artifact_sha256"], "transport artifact")
    if seen != expected:
        raise VerificationError("transport breakdown matrix incomplete")


def validate_bounded_records(value: Any, observations: dict[tuple[str, str], int], request: dict[str, Any]) -> None:
    rows = list_of(value, "bounded records", len(WORKLOADS))
    if len(rows) != len(WORKLOADS):
        raise VerificationError("wrong bounded-record count")
    seen = set()
    root_sizes = set()
    witness_sizes = set()
    for row in rows:
        row = exact(row, RESULT_BINDING_KEYS | {"scenario_id", "media_class", "query_class", "slice", "percentile", "root_bytes", "witness_bytes", "artifact_sha256"}, "bounded record")
        workload = validate_result_binding(row, request, "bounded record")
        if workload in seen or workload not in WORKLOAD_SPECS:
            raise VerificationError("duplicate bounded-record workload")
        seen.add(workload)
        root = integer(row["root_bytes"], "root bytes", 1)
        witness = integer(row["witness_bytes"], "witness bytes", 1)
        if ((row["scenario_id"], row["media_class"], row["query_class"], row["slice"], row["percentile"]) !=
                ("scale-hot-user-writes", "none", "none", "root_and_witness", "maximum") or
                root > MAX_ROOT_BYTES or witness > MAX_WITNESS_BYTES):
            raise VerificationError("root/witness hard cap or dimension failure")
        root_sizes.add(root)
        witness_sizes.add(witness)
        hash_field(row["artifact_sha256"], "bounded-record artifact")
    if (seen != set(WORKLOADS) or len(root_sizes) != 1 or len(witness_sizes) != 1 or
            any(observations[(workload, "root_object_growth_bytes_per_gib")] != 0 or observations[(workload, "witness_record_growth_bytes_per_gib")] != 0 for workload in WORKLOADS) or
            any(next(row["root_bytes"] for row in rows if row["workload_id"] == workload) != observations[(workload, "root_max_bytes")] or next(row["witness_bytes"] for row in rows if row["workload_id"] == workload) != observations[(workload, "witness_max_bytes")] for workload in WORKLOADS)):
        raise VerificationError("root/witness records are not independently bounded")


def validate_report(value: Any, policy: dict[str, Any], request: dict[str, Any], ledger: dict[str, Any], time_assertion: dict[str, Any]) -> dict[str, Any]:
    report = exact(value, {"schema", "contract_id", "activation_blockers", "policy_sha256", "request_sha256", "ledger_sha256", "time_assertion_sha256", "release", "environment", "evaluator", "evidence", "signature_binding", "artifact_bindings", "workloads", "case_results", "measurements", "transport_breakdowns", "durable_write_samples", "durable_write_summaries", "ann_results", "bounded_records", "invariants", "correctness", "cleanup"}, "report")
    if report["schema"] != SCHEMA or report["contract_id"] != policy["contract_id"]:
        raise VerificationError("wrong report contract")
    exact_string_list(report["activation_blockers"], ACTIVATION_BLOCKERS, "activation blockers")
    bindings = (("policy_sha256", policy), ("request_sha256", request), ("ledger_sha256", ledger), ("time_assertion_sha256", time_assertion))
    for field, external in bindings:
        if hash_field(report[field], field) != sha256(canonical(external)):
            raise VerificationError("external wrapper binding mismatch")
    if report["release"] != request["release"] or report["environment"] != request["environment"] or report["artifact_bindings"] != request["artifact_bindings"]:
        raise VerificationError("request/report binding mismatch")
    evaluator = exact(report["evaluator"], {"id", "organization", "tool_sha256", "container_sha256", "test_plan_sha256", "test_config_sha256"}, "evaluator")
    for field in ("tool_sha256", "container_sha256", "test_plan_sha256", "test_config_sha256"):
        hash_field(evaluator[field], field)
    evidence = exact(report["evidence"], {"nonce", "issued_at", "expires_at", "run_id", "synthetic_only", "partial_results"}, "evidence")
    nonce = string(evidence["nonce"], "evidence nonce", NONCE)
    issued = iso_time(evidence["issued_at"], "evidence issued")
    expires = iso_time(evidence["expires_at"], "evidence expiry")
    string(evidence["run_id"], "run id", UUID)
    asserted_now = iso_time(time_assertion["asserted_now"], "asserted now")
    if nonce != request["nonce"] or nonce in ledger["consumed_nonces"] or type(evidence["synthetic_only"]) is not bool or evidence["synthetic_only"] or type(evidence["partial_results"]) is not bool or evidence["partial_results"]:
        raise VerificationError("replay, synthetic, or partial evidence")
    if expires <= issued or expires - issued > timedelta(seconds=policy["max_validity_seconds"]) or asserted_now > expires or issued - asserted_now > timedelta(seconds=policy["max_future_skew_seconds"]) or asserted_now - issued > timedelta(seconds=policy["max_evidence_age_seconds"]):
        raise VerificationError("evidence freshness failure")
    signature_binding = exact(report["signature_binding"], {"kms_key_version", "public_key_spki_der_sha256", "metadata_raw_sha256", "metadata_canonical_sha256", "algorithm", "rotation_status"}, "signature binding")
    if signature_binding["algorithm"] != "EC_SIGN_P256_SHA256" or signature_binding["rotation_status"] != "active":
        raise VerificationError("wrong signature binding")
    signer = next((item for item in policy["trusted_signers"] if all(signature_binding[key] == item[key] for key in ("kms_key_version", "public_key_spki_der_sha256", "metadata_raw_sha256", "metadata_canonical_sha256", "rotation_status"))), None)
    if signer is None or evaluator["id"] != signer["evaluator_id"] or evaluator["organization"] != signer["evaluator_organization"] or evaluator["tool_sha256"] != signer["evaluator_tool_sha256"] or evaluator["container_sha256"] != signer["evaluator_container_sha256"]:
        raise VerificationError("untrusted signer or evaluator")
    if evaluator["test_plan_sha256"] != request["artifact_bindings"]["test_plan"]["raw_sha256"] or evaluator["test_config_sha256"] != request["artifact_bindings"]["test_config"]["raw_sha256"]:
        raise VerificationError("evaluator plan/config mismatch")
    fixture_hash = request["artifact_bindings"]["fixture_manifest"]["raw_sha256"]
    validate_workloads(report["workloads"], fixture_hash)
    validate_cases(report["case_results"], request)
    observations = validate_measurements(report["measurements"], policy, request)
    validate_transport_breakdowns(report["transport_breakdowns"], request, observations)
    write_growth = validate_write_samples(report["durable_write_samples"], report["durable_write_summaries"], request)
    if any(observations[key] != derived for key, derived in write_growth.items()):
        raise VerificationError("write growth measurement contradicts raw live-size traces")
    validate_ann(report["ann_results"], fixture_hash, request["environment"]["query_mode"], request)
    validate_bounded_records(report["bounded_records"], observations, request)
    invariants = exact(report["invariants"], set(INVARIANTS), "invariants")
    if any(type(invariants[key]) is not bool or not invariants[key] for key in INVARIANTS):
        raise VerificationError("categorical invariant failure")
    correctness = exact(report["correctness"], {"logical_export_legacy_sha256", "logical_export_archive_sha256", "mismatches", "integrity_artifact_sha256"}, "correctness")
    if hash_field(correctness["logical_export_legacy_sha256"], "legacy export") != hash_field(correctness["logical_export_archive_sha256"], "archive export") or integer(correctness["mismatches"], "mismatches") != 0:
        raise VerificationError("correctness contradiction")
    hash_field(correctness["integrity_artifact_sha256"], "integrity artifact")
    cleanup = exact(report["cleanup"], {"residual_objects", "provider_recovery_mode", "provider_recovery_deadline_ms", "physical_delete_elapsed_ms", "zero_inventory_artifact_sha256", "idempotency_artifact_sha256"}, "cleanup")
    deadline = integer(cleanup["provider_recovery_deadline_ms"], "cleanup recovery deadline")
    elapsed = integer(cleanup["physical_delete_elapsed_ms"], "physical delete elapsed")
    if integer(cleanup["residual_objects"], "residual objects") != 0 or cleanup["provider_recovery_mode"] != request["environment"]["provider_recovery_mode"] or deadline != request["environment"]["provider_recovery_deadline_ms"]:
        raise VerificationError("cleanup binding failure")
    post_recovery = elapsed if cleanup["provider_recovery_mode"] == "disabled" else max(0, elapsed - deadline)
    if any(post_recovery != observations[(workload, "physical_deletion_post_recovery_ms")] for workload in WORKLOADS) or post_recovery > 86400000:
        raise VerificationError("physical deletion conditional failure")
    hash_field(cleanup["zero_inventory_artifact_sha256"], "zero inventory artifact")
    hash_field(cleanup["idempotency_artifact_sha256"], "idempotency artifact")
    return report


def der_length(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise VerificationError("truncated DER")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    count = first & 0x7F
    if count == 0 or count > 2 or offset + 1 + count > len(data):
        raise VerificationError("noncanonical DER length")
    raw = data[offset + 1:offset + 1 + count]
    if raw[0] == 0:
        raise VerificationError("noncanonical DER length")
    length = int.from_bytes(raw, "big")
    if length < 0x80:
        raise VerificationError("noncanonical DER length")
    return length, offset + 1 + count


def der_item(data: bytes, offset: int, tag: int) -> tuple[bytes, int]:
    if offset >= len(data) or data[offset] != tag:
        raise VerificationError("unexpected DER tag")
    length, start = der_length(data, offset + 1)
    end = start + length
    if end > len(data):
        raise VerificationError("truncated DER item")
    return data[start:end], end


def decode_p256_spki(pem: str) -> bytes:
    lines = pem.splitlines()
    if len(pem.encode("ascii")) > MAX_PEM_BYTES or len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        raise VerificationError("invalid SPKI PEM envelope")
    body = "".join(lines[1:-1])
    try:
        der = base64.b64decode(body, validate=True)
    except Exception as error:
        raise VerificationError("invalid SPKI base64") from error
    outer, end = der_item(der, 0, 0x30)
    if end != len(der):
        raise VerificationError("trailing SPKI DER")
    algorithm, offset = der_item(outer, 0, 0x30)
    point, offset = der_item(outer, offset, 0x03)
    if offset != len(outer):
        raise VerificationError("extra SPKI fields")
    ec_oid, aoff = der_item(algorithm, 0, 0x06)
    curve_oid, aoff = der_item(algorithm, aoff, 0x06)
    if aoff != len(algorithm) or ec_oid != bytes.fromhex("2a8648ce3d0201") or curve_oid != bytes.fromhex("2a8648ce3d030107"):
        raise VerificationError("SPKI is not EC prime256v1/P-256")
    if len(point) != 66 or point[0] != 0 or point[1] != 4:
        raise VerificationError("P-256 key must be uncompressed SEC1 point")
    return der


def validate_ecdsa_der(signature: bytes) -> None:
    if not 8 <= len(signature) <= 72:
        raise VerificationError("invalid P-256 ECDSA signature size")
    sequence, end = der_item(signature, 0, 0x30)
    if end != len(signature):
        raise VerificationError("trailing signature DER")
    offset = 0
    for _ in range(2):
        integer_bytes, offset = der_item(sequence, offset, 0x02)
        if not integer_bytes or len(integer_bytes) > 33 or integer_bytes[0] & 0x80 or (len(integer_bytes) > 1 and integer_bytes[0] == 0 and not integer_bytes[1] & 0x80):
            raise VerificationError("noncanonical ECDSA integer")
    if offset != len(sequence):
        raise VerificationError("wrong ECDSA signature shape")


def verify_signature(payload: bytes, signature_path: Path, metadata_path: Path, signer: dict[str, Any], openssl_path: Path, openssl_hash: str) -> None:
    if not openssl_path.is_absolute():
        raise VerificationError("openssl path must be absolute")
    executable = read_regular(openssl_path, MAX_OPENSSL_BYTES, "openssl executable")
    if sha256(executable) != openssl_hash:
        raise VerificationError("untrusted openssl executable")
    metadata, metadata_raw = load_json(metadata_path)
    metadata = exact(metadata, {"schema", "kms_key_version", "algorithm", "rotation_status", "public_key_spki_pem"}, "pinned public-key metadata")
    if metadata["schema"] != KEY_SCHEMA or metadata["kms_key_version"] != signer["kms_key_version"] or metadata["algorithm"] != "EC_SIGN_P256_SHA256" or metadata["rotation_status"] != "active":
        raise VerificationError("public-key metadata mismatch")
    pem = string(metadata["public_key_spki_pem"], "SPKI PEM")
    spki_der = decode_p256_spki(pem)
    if sha256(spki_der) != signer["public_key_spki_der_sha256"] or sha256(metadata_raw) != signer["metadata_raw_sha256"] or sha256(canonical(metadata)) != signer["metadata_canonical_sha256"]:
        raise VerificationError("pinned public-key hash mismatch")
    signature_encoded = read_regular(signature_path, MAX_SIGNATURE_B64_BYTES, "signature")
    try:
        signature = base64.b64decode(signature_encoded, validate=True)
    except Exception as error:
        raise VerificationError("signature must be strict base64 DER") from error
    validate_ecdsa_der(signature)
    with tempfile.TemporaryDirectory(prefix="kioku-capacity-verify-") as directory:
        root = Path(directory)
        verifier = root / "openssl"
        verifier.write_bytes(executable)
        verifier.chmod(0o700)
        report_file = root / "report.json"
        key_file = root / "key.pem"
        signature_file = root / "signature.der"
        report_file.write_bytes(payload)
        key_file.write_text(pem, encoding="ascii")
        signature_file.write_bytes(signature)
        verifier_environment = {
            "HOME": str(root),
            "LANG": "C",
            "LC_ALL": "C",
            "OPENSSL_CONF": "/dev/null",
            "TMPDIR": str(root),
        }
        try:
            completed = subprocess.run(
                [str(verifier), "dgst", "-sha256", "-verify", str(key_file),
                 "-signature", str(signature_file), str(report_file)],
                capture_output=True, text=True, timeout=10, check=False,
                cwd=root, env=verifier_environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise VerificationError("signature verifier unavailable") from error
    if completed.returncode != 0:
        raise VerificationError("P-256 SHA-256 signature verification failed")


def report_replay_sha256(report: dict[str, Any]) -> str:
    """Stable report replay key, excluding only the ledger snapshot that consumes it."""
    replay_view = dict(report)
    replay_view["ledger_sha256"] = "0" * 64
    return sha256(canonical(replay_view))


def verify(report_path: Path, digest_path: Path, signature_path: Path, key_metadata_path: Path, policy_path: Path, request_path: Path, ledger_path: Path, time_assertion_path: Path, artifact_paths: dict[str, Path], openssl_path: Path, local_now: datetime | None = None) -> dict[str, Any]:
    policy, _ = load_json(policy_path)
    policy = validate_policy(policy)
    request, _ = load_json(request_path)
    request = validate_request(request, policy)
    ledger, _ = load_json(ledger_path)
    ledger = validate_ledger(ledger)
    time_assertion, _ = load_json(time_assertion_path)
    time_assertion = validate_time_assertion(time_assertion, policy, local_now or datetime.now(timezone.utc))
    validate_artifacts(request, artifact_paths)
    report, _ = load_json(report_path)
    payload = canonical(report)
    report_hash = sha256(payload)
    report_replay_hash = report_replay_sha256(report)
    try:
        digest = read_regular(digest_path, MAX_DIGEST_BYTES, "report digest").decode("ascii").strip()
    except UnicodeError as error:
        raise VerificationError("report digest must be ASCII") from error
    request_hash = sha256(canonical(request))
    if hash_field(digest, "report digest") != report_hash or report_replay_hash in ledger["consumed_report_sha256"] or request_hash in ledger["consumed_request_sha256"]:
        raise VerificationError("digest or replay snapshot rejection")
    report = validate_report(report, policy, request, ledger, time_assertion)
    signer = next(item for item in policy["trusted_signers"] if item["kms_key_version"] == report["signature_binding"]["kms_key_version"])
    verify_signature(payload, signature_path, key_metadata_path, signer, openssl_path, policy["openssl_sha256"])
    return {
        "schema": RECEIPT_SCHEMA,
        "preauthorization_only": True,
        "authority": False,
        "activation_blockers": list(ACTIVATION_BLOCKERS),
        "report_sha256": report_hash,
        "report_replay_sha256": report_replay_hash,
        "request_sha256": request_hash,
        "nonce": request["nonce"],
        "ledger_sha256": sha256(canonical(ledger)),
        "ledger_sequence": ledger["sequence"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("report", "report_digest", "signature", "public_key_metadata", "policy", "verification_request", "replay_ledger", "time_assertion", "release_manifest", "provenance", "sbom", "fixture_manifest", "test_plan", "test_config", "environment_attestation", "openssl"):
        parser.add_argument("--" + argument.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args()
    artifacts = {name: getattr(args, name) for name in ARTIFACTS}
    try:
        receipt = verify(args.report, args.report_digest, args.signature, args.public_key_metadata, args.policy, args.verification_request, args.replay_ledger, args.time_assertion, artifacts, args.openssl)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (VerificationError, UnicodeError) as error:
        print(f"capacity evidence rejected: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
