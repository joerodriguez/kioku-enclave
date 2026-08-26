#!/usr/bin/env python3
"""Exact source/configuration contracts for the two ADR-0022 fresh releases.

This module is deliberately provider-free.  It binds signed release metadata to
the reviewed checked-in namespace intent and to two opaque values supplied by
the private production operator configuration: the owner-sealed canary identity
receipt hash and the sole derived canary administrator UUID.  The FINAL role is
reserved here before its live binding exists; a tree remains ineligible until
its checked runtime, seal, and schema declarations are the exact active form.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_TAG = "v0.8.35-adr0022-fresh-bootstrap.1"
FINAL_TAG = "v0.8.35-archive-v3-wal.4"
SOURCE_REPOSITORY = "https://github.com/joerodriguez/kioku-enclave"
GENERATION_INTENT_SHA256 = (
    "7ece5ba914f76d2f56af178d5891230d3e1ba7df33a6b54dd3d2a7870cce3727"
)
SCHEMA10_BOOTSTRAP_FIXTURE_SHA256 = (
    "40ce2530b9860133f69ac2d207c0f86165b6971b7207329ed7d09b3a4516e2a9"
)
# BOOTSTRAP carried this as an empty string. FINAL pins the exact SHA-256 of
# its completed baseline-seal bytes, so merely flipping ``sealed`` or
# activating the runtime cannot make another tree eligible for publication.
FINAL_SCHEMA_BASELINE_SEAL_SHA256 = (
    "013f5f9698a20012a0e0833f3241e52395a6a26411627e5c07fe8f2833a386ed"
)
NAMESPACE_ID = "adr0022-v1"
PROJECT_ID = "kioku-joerodriguez"
PROJECT_NUMBER = "640329636251"
REGION = "us-central1"
IMAGE_REPOSITORY = (
    "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave"
)
CANARY_CONFIG_KEY = "ADR0022_CANARY_IDENTITY_PREPARATION_SHA256"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UUID_V5 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)

EXPECTED_INTENT = {
    "schema": "kioku-adr0022-fresh-generation-intent-v1",
    "namespace_id": NAMESPACE_ID,
    "project_id": PROJECT_ID,
    "project_number": PROJECT_NUMBER,
    "region": REGION,
    "image_repository": IMAGE_REPOSITORY,
    "index_bucket": "kioku-joerodriguez-adr0022-v1-indexes",
    "media_bucket": "kioku-joerodriguez-adr0022-v1-media",
    "legacy_media_bucket": "kioku-joerodriguez-adr0022-v1-indexes",
    "archive_bucket": "kioku-joerodriguez-adr0022-v1-archive",
    "witness_backup_bucket": "kioku-joerodriguez-adr0022-v1-witness-backups",
    "witness_database_id": "adr0022-v1-witness",
    "kms_key_version": (
        "projects/kioku-joerodriguez/locations/us-central1/keyRings/"
        "kioku-adr0022-v1/cryptoKeys/kioku-kek-adr0022-v1/cryptoKeyVersions/1"
    ),
    "runtime_service_account": (
        "kioku-enclave-adr0022-v1@kioku-joerodriguez.iam.gserviceaccount.com"
    ),
    "main_wif_provider": (
        "projects/640329636251/locations/global/workloadIdentityPools/"
        "enclave-attest/providers/attest"
    ),
    "archive_gcs_wif_provider": (
        "projects/640329636251/locations/global/workloadIdentityPools/"
        "archive-gcs-attest/providers/archive-gcs"
    ),
    "archive_witness_wif_provider": (
        "projects/640329636251/locations/global/workloadIdentityPools/"
        "archive-witness-attest/providers/archive-witness"
    ),
    "archive_object_writer_role": (
        "projects/kioku-joerodriguez/roles/kiokuAdr0022V1ArchiveObjectWriter"
    ),
    "witness_writer_role": (
        "projects/kioku-joerodriguez/roles/kiokuAdr0022V1WitnessWriter"
    ),
    "public_deny_firewall": "kioku-adr0022-cutover-deny",
}

RELEASE_BINDING_FIELD_ORDER = (
    "adr0022_generation_intent_sha256",
    "adr0022_namespace_id",
    "adr0022_project_id",
    "adr0022_project_number",
    "adr0022_archive_bucket",
    "adr0022_witness_database_id",
    "adr0022_kms_project_id",
    "adr0022_kms_location",
    "adr0022_kms_key_ring",
    "adr0022_kms_key",
    "adr0022_kms_key_version",
    "adr0022_runtime_service_account",
    "adr0022_main_wif_provider",
    "adr0022_archive_gcs_wif_provider",
    "adr0022_archive_witness_wif_provider",
    "adr0022_archive_object_writer_role",
    "adr0022_witness_writer_role",
    "adr0022_canary_identity_preparation_sha256",
    "adr0022_canary_admin_uuid",
    "production_genesis_wal_native",
    "schema_epoch_head",
    "schema_epoch_target",
    "schema_epoch_minimum_servable",
    "signup_mode",
)

_EXPECTED_COMMON_CONFIGURATION = {
    "PROJECT_ID": PROJECT_ID,
    "REGION": REGION,
    "AR_REPOSITORY": "kioku",
    "IMAGE_NAME": "kioku-enclave",
    "ENCLAVE_KMS_PROJECT": PROJECT_ID,
    "ENCLAVE_KMS_LOCATION": REGION,
    "ENCLAVE_KMS_KEY_RING": "kioku-adr0022-v1",
    "ENCLAVE_KMS_KEY": "kioku-kek-adr0022-v1",
    "ENCLAVE_GCS_BUCKET": EXPECTED_INTENT["index_bucket"],
    "ENCLAVE_GCS_MEDIA_BUCKET": EXPECTED_INTENT["media_bucket"],
    "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET": EXPECTED_INTENT["legacy_media_bucket"],
    "ENCLAVE_RUN_SA_EMAIL": EXPECTED_INTENT["runtime_service_account"],
    "ENCLAVE_ATTEST_STS_AUDIENCE": (
        "//iam.googleapis.com/" + EXPECTED_INTENT["main_wif_provider"]
    ),
}

_EXPECTED_BOOTSTRAP_CONFIGURATION = {
    **_EXPECTED_COMMON_CONFIGURATION,
    "ARCHIVE_WITNESS_SHADOW_MODE": "off",
    "ARCHIVE_WITNESS_PROJECT_ID": "",
    "ARCHIVE_WITNESS_PROJECT_NUMBER": "",
    "ARCHIVE_WITNESS_DATABASE_ID": "",
    "ARCHIVE_V3_SHADOW_RUNTIME_MODE": "off",
    "ARCHIVE_V3_ARCHIVE_BUCKET": "",
    "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER": "",
    "ARCHIVE_V3_REGISTRY_KMS_VERSION": "",
    "ARCHIVE_V3_WITNESS_PROJECT_ID": "",
    "ARCHIVE_V3_WITNESS_PROJECT_NUMBER": "",
    "ARCHIVE_V3_WITNESS_DATABASE_ID": "",
    "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT": "",
    "GENESIS_WAL_NATIVE": "off",
}

_EXPECTED_FINAL_CONFIGURATION = {
    **_EXPECTED_COMMON_CONFIGURATION,
    "ARCHIVE_WITNESS_SHADOW_MODE": "off",
    "ARCHIVE_WITNESS_PROJECT_ID": "",
    "ARCHIVE_WITNESS_PROJECT_NUMBER": "",
    "ARCHIVE_WITNESS_DATABASE_ID": "",
    "ARCHIVE_V3_SHADOW_RUNTIME_MODE": "single-archive-wal-v1",
    "ARCHIVE_V3_ARCHIVE_BUCKET": EXPECTED_INTENT["archive_bucket"],
    "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER": PROJECT_NUMBER,
    "ARCHIVE_V3_REGISTRY_KMS_VERSION": "1",
    "ARCHIVE_V3_WITNESS_PROJECT_ID": PROJECT_ID,
    "ARCHIVE_V3_WITNESS_PROJECT_NUMBER": PROJECT_NUMBER,
    "ARCHIVE_V3_WITNESS_DATABASE_ID": EXPECTED_INTENT["witness_database_id"],
    "GENESIS_WAL_NATIVE": "on",
}

_EXPECTED_SCHEMA_PHASE_FRAGMENT = """
pub(crate) const SCHEMA_LADDER: &[SchemaStep] = &[];

pub(crate) const SCHEMA_EPOCH_HEAD: u32 = 0;

pub(crate) const SCHEMA_EPOCH_TARGET: u32 = 0;

pub(crate) const SCHEMA_EPOCH_MIN_SERVABLE: u32 = 0;
"""

_EXPECTED_FINAL_SCHEMA_PHASE_FRAGMENT = """
pub(crate) const SCHEMA_LADDER: &[SchemaStep] = &[SchemaStep {
    epoch: 1,
    id: "0001_capture_events_stream_sequence",
    class: StepClass::Index,
    sql: "CREATE INDEX idx_capture_events_stream_sequence ON capture_events (stream_id, sequence);",
}];

pub(crate) const SCHEMA_EPOCH_HEAD: u32 = 1;

pub(crate) const SCHEMA_EPOCH_TARGET: u32 = 1;

pub(crate) const SCHEMA_EPOCH_MIN_SERVABLE: u32 = 1;
"""


class FreshReleaseError(ValueError):
    """One fresh release coordinate or source invariant is not exact."""


class DuplicateName(ValueError):
    pass


def _exact_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise DuplicateName("duplicate JSON name")
        result[name] = value
    return result


def normalize_tag(source_ref: str) -> str:
    return source_ref.removeprefix("refs/tags/")


def claims_bootstrap_role(source_ref: str) -> bool:
    """Return true for every release ref attempting to name this fixed role."""

    return "adr0022-fresh-bootstrap" in normalize_tag(source_ref).lower()


def claims_final_role(source_ref: str) -> bool:
    """Return true for every 0.8.35 WAL ref attempting the fixed FINAL role."""

    return normalize_tag(source_ref).lower().startswith(
        "v0.8.35-archive-v3-wal"
    )


def claims_fresh_role(source_ref: str) -> bool:
    return claims_bootstrap_role(source_ref) or claims_final_role(source_ref)


def is_bootstrap_tag(source_ref: str) -> bool:
    return normalize_tag(source_ref) == BOOTSTRAP_TAG


def require_exact_bootstrap_tag(source_ref: str) -> None:
    if not is_bootstrap_tag(source_ref):
        raise FreshReleaseError(
            f"fresh BOOTSTRAP source_ref must be exactly {BOOTSTRAP_TAG}"
        )


def is_final_tag(source_ref: str) -> bool:
    return normalize_tag(source_ref) == FINAL_TAG


def require_exact_final_tag(source_ref: str) -> None:
    if not is_final_tag(source_ref):
        raise FreshReleaseError(
            f"fresh FINAL source_ref must be exactly {FINAL_TAG}"
        )


def require_exact_fresh_tag(source_ref: str) -> None:
    if claims_bootstrap_role(source_ref):
        require_exact_bootstrap_tag(source_ref)
        return
    if claims_final_role(source_ref):
        require_exact_final_tag(source_ref)
        return
    raise FreshReleaseError("source_ref does not name an ADR-0022 fresh release role")


def validate_generation_intent(path: Path | None = None) -> dict[str, Any]:
    path = path or ROOT / "config/adr0022-fresh-generation-intent.json"
    try:
        raw = path.read_bytes()
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_exact_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, DuplicateName) as error:
        raise FreshReleaseError("fresh generation intent is invalid") from error
    if not isinstance(payload, dict) or payload != EXPECTED_INTENT:
        raise FreshReleaseError("fresh generation intent is not the reviewed exact tuple")
    if hashlib.sha256(raw).hexdigest() != GENERATION_INTENT_SHA256:
        raise FreshReleaseError("fresh generation intent bytes are not canonical")
    return payload


def validate_checked_bootstrap_source(root: Path | None = None) -> None:
    root = root or ROOT
    validate_generation_intent(root / "config/adr0022-fresh-generation-intent.json")
    try:
        manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
        schema = (root / "src/schema_ladder.rs").read_text(encoding="utf-8")
        probe = json.loads(
            (root / "config/archive-witness-probe.json").read_text(encoding="utf-8"),
            object_pairs_hook=_exact_object,
        )
        runtime = json.loads(
            (root / "config/archive-v3-shadow-runtime.json").read_text(
                encoding="utf-8"
            ),
            object_pairs_hook=_exact_object,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        DuplicateName,
    ) as error:
        raise FreshReleaseError("fresh BOOTSTRAP checked source is unreadable") from error
    if manifest.get("package", {}).get("version") != "0.8.35":
        raise FreshReleaseError("fresh BOOTSTRAP Cargo version must be 0.8.35")
    package_versions = [
        package.get("version")
        for package in lock.get("package", [])
        if package.get("name") == "kioku-enclave"
    ]
    if package_versions != ["0.8.35"]:
        raise FreshReleaseError("fresh BOOTSTRAP lockfile version must be 0.8.35")
    begin = "// ADR0022_SCHEMA_PHASE_DECLARATION_BEGIN"
    end = "// ADR0022_SCHEMA_PHASE_DECLARATION_END"
    if schema.count(begin) != 1 or schema.count(end) != 1:
        raise FreshReleaseError("schema phase declaration delimiters are not exact")
    fragment = schema.split(begin, 1)[1].split(end, 1)[0]
    if fragment != _EXPECTED_SCHEMA_PHASE_FRAGMENT:
        raise FreshReleaseError("fresh BOOTSTRAP schema phase is not exact 0/0/0")
    if probe != {
        "schema_version": 1,
        "mode": "off",
        "project_id": "",
        "project_number": "",
        "database_id": "",
    }:
        raise FreshReleaseError("fresh BOOTSTRAP witness probe is not exact off")
    if runtime != {
        "schema_version": 2,
        "mode": "off",
        "archive_bucket": "",
        "archive_gcs_project_number": "",
        "registry_kms_version": "",
        "witness_project_id": "",
        "witness_project_number": "",
        "witness_database_id": "",
        "archive_binding_commitment": "",
    }:
        raise FreshReleaseError("fresh BOOTSTRAP archive runtime is not exact off")


def validate_checked_final_source(root: Path | None = None) -> str:
    """Validate the exact active FINAL source and return its live commitment."""

    root = root or ROOT
    validate_generation_intent(root / "config/adr0022-fresh-generation-intent.json")
    try:
        manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
        lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
        schema = (root / "src/schema_ladder.rs").read_text(encoding="utf-8")
        seal_raw = (root / "scripts/schema_baseline_seal.json").read_bytes()
        seal = json.loads(
            seal_raw.decode("utf-8"),
            object_pairs_hook=_exact_object,
        )
        probe = json.loads(
            (root / "config/archive-witness-probe.json").read_text(encoding="utf-8"),
            object_pairs_hook=_exact_object,
        )
        runtime = json.loads(
            (root / "config/archive-v3-shadow-runtime.json").read_text(
                encoding="utf-8"
            ),
            object_pairs_hook=_exact_object,
        )
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
        DuplicateName,
    ) as error:
        raise FreshReleaseError("fresh FINAL checked source is unreadable") from error
    if manifest.get("package", {}).get("version") != "0.8.35":
        raise FreshReleaseError("fresh FINAL Cargo version must be 0.8.35")
    package_versions = [
        package.get("version")
        for package in lock.get("package", [])
        if package.get("name") == "kioku-enclave"
    ]
    if package_versions != ["0.8.35"]:
        raise FreshReleaseError("fresh FINAL lockfile version must be 0.8.35")
    begin = "// ADR0022_SCHEMA_PHASE_DECLARATION_BEGIN"
    end = "// ADR0022_SCHEMA_PHASE_DECLARATION_END"
    if schema.count(begin) != 1 or schema.count(end) != 1:
        raise FreshReleaseError("schema phase declaration delimiters are not exact")
    fragment = schema.split(begin, 1)[1].split(end, 1)[0]
    if fragment != _EXPECTED_FINAL_SCHEMA_PHASE_FRAGMENT:
        raise FreshReleaseError("fresh FINAL schema phase is not exact 1/1/1")
    if (
        HEX64.fullmatch(FINAL_SCHEMA_BASELINE_SEAL_SHA256) is None
        or FINAL_SCHEMA_BASELINE_SEAL_SHA256 == "0" * 64
        or hashlib.sha256(seal_raw).hexdigest()
        != FINAL_SCHEMA_BASELINE_SEAL_SHA256
    ):
        raise FreshReleaseError("fresh FINAL schema baseline seal is not pinned")
    if (
        not isinstance(seal, dict)
        or set(seal) != {"_comment", "sealed", "digest", "history"}
        or seal.get("sealed") is not True
    ):
        raise FreshReleaseError("fresh FINAL schema baseline is not sealed")
    history = seal.get("history")
    if (
        not isinstance(seal.get("digest"), str)
        or HEX64.fullmatch(seal["digest"]) is None
        or seal["digest"] == "0" * 64
        or not isinstance(history, list)
        or not history
        or not isinstance(history[-1], dict)
        or history[-1].get("digest") != seal["digest"]
        or not isinstance(history[-1].get("chain"), str)
        or HEX64.fullmatch(history[-1]["chain"]) is None
        or history[-1]["chain"] == "0" * 64
    ):
        raise FreshReleaseError("fresh FINAL schema baseline history is invalid")
    if probe != {
        "schema_version": 1,
        "mode": "off",
        "project_id": "",
        "project_number": "",
        "database_id": "",
    }:
        raise FreshReleaseError("fresh FINAL witness probe is not exact off")
    expected_runtime = {
        "schema_version": 2,
        "mode": "single-archive-wal-v1",
        "archive_bucket": EXPECTED_INTENT["archive_bucket"],
        "archive_gcs_project_number": PROJECT_NUMBER,
        "registry_kms_version": "1",
        "witness_project_id": PROJECT_ID,
        "witness_project_number": PROJECT_NUMBER,
        "witness_database_id": EXPECTED_INTENT["witness_database_id"],
    }
    if not isinstance(runtime, dict) or {
        name: runtime.get(name) for name in expected_runtime
    } != expected_runtime or set(runtime) != {
        *expected_runtime,
        "archive_binding_commitment",
    }:
        raise FreshReleaseError("fresh FINAL archive runtime is not exact active")
    commitment = runtime.get("archive_binding_commitment")
    if (
        not isinstance(commitment, str)
        or HEX64.fullmatch(commitment) is None
        or commitment == "0" * 64
    ):
        raise FreshReleaseError("fresh FINAL archive binding commitment is invalid")
    return commitment


def validate_canary_binding(receipt_sha256: str, admin_uuid: str) -> None:
    if HEX64.fullmatch(receipt_sha256) is None or receipt_sha256 == "0" * 64:
        raise FreshReleaseError(
            "fresh canary identity preparation SHA-256 must be nonzero lowercase hex"
        )
    if UUID_V5.fullmatch(admin_uuid) is None:
        raise FreshReleaseError("fresh canary administrator must be a lowercase UUIDv5")


def validate_bootstrap_configuration(configuration: dict[str, str]) -> None:
    validate_checked_bootstrap_source()
    for name, expected in _EXPECTED_BOOTSTRAP_CONFIGURATION.items():
        if configuration.get(name) != expected:
            raise FreshReleaseError(
                f"fresh BOOTSTRAP configuration does not match reviewed {name}"
            )
    signup_limit = configuration.get("SIGNUP_LIMIT_PER_DAY", "")
    if re.fullmatch(r"[1-9][0-9]{0,6}", signup_limit) is None:
        raise FreshReleaseError("fresh BOOTSTRAP signup mode must be positive")
    receipt_sha256 = configuration.get(CANARY_CONFIG_KEY, "")
    admin_uuid = configuration.get("ADMIN_USER_IDS", "")
    validate_canary_binding(receipt_sha256, admin_uuid)


def validate_final_configuration(configuration: dict[str, str]) -> None:
    commitment = validate_checked_final_source()
    for name, expected in _EXPECTED_FINAL_CONFIGURATION.items():
        if configuration.get(name) != expected:
            raise FreshReleaseError(
                f"fresh FINAL configuration does not match reviewed {name}"
            )
    if configuration.get("ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT") != commitment:
        raise FreshReleaseError(
            "fresh FINAL configuration does not match the checked binding commitment"
        )
    signup_limit = configuration.get("SIGNUP_LIMIT_PER_DAY", "")
    if re.fullmatch(r"[1-9][0-9]{0,6}", signup_limit) is None:
        raise FreshReleaseError("fresh FINAL signup mode must be positive")
    validate_canary_binding(
        configuration.get(CANARY_CONFIG_KEY, ""),
        configuration.get("ADMIN_USER_IDS", ""),
    )


def _release_binding(
    canary_identity_preparation_sha256: str,
    canary_admin_uuid: str,
    *,
    genesis: str,
    epoch: int,
) -> dict[str, Any]:
    validate_canary_binding(canary_identity_preparation_sha256, canary_admin_uuid)
    binding: dict[str, Any] = {
        "adr0022_generation_intent_sha256": GENERATION_INTENT_SHA256,
        "adr0022_namespace_id": NAMESPACE_ID,
        "adr0022_project_id": PROJECT_ID,
        "adr0022_project_number": PROJECT_NUMBER,
        "adr0022_archive_bucket": EXPECTED_INTENT["archive_bucket"],
        "adr0022_witness_database_id": EXPECTED_INTENT["witness_database_id"],
        "adr0022_kms_project_id": PROJECT_ID,
        "adr0022_kms_location": REGION,
        "adr0022_kms_key_ring": "kioku-adr0022-v1",
        "adr0022_kms_key": "kioku-kek-adr0022-v1",
        "adr0022_kms_key_version": EXPECTED_INTENT["kms_key_version"],
        "adr0022_runtime_service_account": EXPECTED_INTENT[
            "runtime_service_account"
        ],
        "adr0022_main_wif_provider": EXPECTED_INTENT["main_wif_provider"],
        "adr0022_archive_gcs_wif_provider": EXPECTED_INTENT[
            "archive_gcs_wif_provider"
        ],
        "adr0022_archive_witness_wif_provider": EXPECTED_INTENT[
            "archive_witness_wif_provider"
        ],
        "adr0022_archive_object_writer_role": EXPECTED_INTENT[
            "archive_object_writer_role"
        ],
        "adr0022_witness_writer_role": EXPECTED_INTENT["witness_writer_role"],
        "adr0022_canary_identity_preparation_sha256": (
            canary_identity_preparation_sha256
        ),
        "adr0022_canary_admin_uuid": canary_admin_uuid,
        "production_genesis_wal_native": genesis,
        "schema_epoch_head": epoch,
        "schema_epoch_target": epoch,
        "schema_epoch_minimum_servable": epoch,
        "signup_mode": "positive",
    }
    if tuple(binding) != RELEASE_BINDING_FIELD_ORDER:
        raise FreshReleaseError("fresh release binding order drifted")
    return binding


def bootstrap_release_binding(
    canary_identity_preparation_sha256: str,
    canary_admin_uuid: str,
) -> dict[str, Any]:
    """Return the exact ordered schema-10-only BOOTSTRAP binding fields."""

    validate_checked_bootstrap_source()
    return _release_binding(
        canary_identity_preparation_sha256,
        canary_admin_uuid,
        genesis="off",
        epoch=0,
    )


def final_release_binding(
    canary_identity_preparation_sha256: str,
    canary_admin_uuid: str,
) -> dict[str, Any]:
    """Return the exact ordered schema-10-only FINAL binding fields."""

    validate_checked_final_source()
    validate_canary_binding(canary_identity_preparation_sha256, canary_admin_uuid)
    binding = _release_binding(
        canary_identity_preparation_sha256,
        canary_admin_uuid,
        genesis="on",
        epoch=1,
    )
    if tuple(binding) != RELEASE_BINDING_FIELD_ORDER:
        raise FreshReleaseError("fresh FINAL release binding order drifted")
    return binding


def bootstrap_release_binding_from_configuration(
    configuration: dict[str, str],
) -> dict[str, Any]:
    validate_bootstrap_configuration(configuration)
    return bootstrap_release_binding(
        configuration[CANARY_CONFIG_KEY], configuration["ADMIN_USER_IDS"]
    )


def final_release_binding_from_configuration(
    configuration: dict[str, str],
) -> dict[str, Any]:
    validate_final_configuration(configuration)
    return final_release_binding(
        configuration[CANARY_CONFIG_KEY], configuration["ADMIN_USER_IDS"]
    )


def fresh_release_binding_from_configuration(
    configuration: dict[str, str], source_ref: str
) -> dict[str, Any]:
    require_exact_fresh_tag(source_ref)
    if is_bootstrap_tag(source_ref):
        return bootstrap_release_binding_from_configuration(configuration)
    return final_release_binding_from_configuration(configuration)
