#!/usr/bin/env python3
"""Select one complete enclave image configuration without cross-profile fallback."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from archive_witness_probe_config import (
    ProbeConfigError,
    load_probe_config,
    select_probe_config,
)
from archive_v3_shadow_runtime_config import (
    ShadowRuntimeConfigError,
    load_shadow_runtime_config,
    select_shadow_runtime_config,
)


SHARED_KEYS = (
    "PROJECT_ID",
    "REGION",
    "AR_REPOSITORY",
    "IMAGE_NAME",
)

PROFILE_KEYS = (
    "ENCLAVE_KMS_PROJECT",
    "ENCLAVE_KMS_LOCATION",
    "ENCLAVE_KMS_KEY_RING",
    "ENCLAVE_KMS_KEY",
    "ENCLAVE_GCS_BUCKET",
    "ENCLAVE_GCS_MEDIA_BUCKET",
    "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET",
    "ENCLAVE_RUN_SA_EMAIL",
    "ENCLAVE_AUDIENCE",
    "ENCLAVE_ATTEST_STS_AUDIENCE",
    "GOOGLE_DESKTOP_CLIENT_ID",
    "GOOGLE_IOS_CLIENT_ID",
    "GOOGLE_WEB_CLIENT_ID",
    "ADMIN_USER_IDS",
    "SIGNUP_LIMIT_PER_DAY",
    "BASE_URL",
    "WEB_ORIGIN",
    "BILLING_SERVICE_URL",
    "BILLING_SERVICE_AUDIENCE",
    "BILLING_ENFORCEMENT_MODE",
    "REVIEWER_AUTH_API_KEY",
    "REVIEWER_AUTH_UID",
    "REVIEWER_AUTH_EMAIL",
    "VERTEX_PROJECT",
    "VERTEX_LOCATION",
    "VERTEX_MODEL",
    "ENCLAVE_ACME",
    "ENCLAVE_ACME_DIRECTORY",
    "ENCLAVE_ACME_CONTACT",
)

OPTIONAL_PROFILE_GROUPS = (
    (
        "APPLE_TEAM_ID",
        "APPLE_KEY_ID",
        "APPLE_IOS_CLIENT_ID",
        "APPLE_MACOS_CLIENT_ID",
        "APPLE_WEB_CLIENT_ID",
    ),
    (
        "APNS_TEAM_ID",
        "APNS_PRODUCTION_KEY_ID",
        "APNS_SANDBOX_KEY_ID",
    ),
)

PROJECT_PATTERN = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
SERVICE_ACCOUNT_PATTERN = (
    r"[a-z0-9][a-z0-9-]{4,28}[a-z0-9]@"
    + PROJECT_PATTERN
    + r"\.iam\.gserviceaccount\.com"
)
EMAIL_PATTERN = r"[^@,\s]+@[^@,\s]+"


def require_value(environment: dict[str, str], name: str) -> str:
    value = environment.get(name, "")
    if not value:
        raise SystemExit(f"missing required build configuration: {name}")
    return value


def reject_control_characters(configuration: dict[str, str]) -> None:
    for name, value in configuration.items():
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise SystemExit(f"control character in build configuration: {name}")


def require_pattern(configuration: dict[str, str], name: str, pattern: str) -> None:
    if not re.fullmatch(pattern, configuration[name]):
        raise SystemExit(f"invalid format for build configuration: {name}")


def require_https_origin(configuration: dict[str, str], name: str) -> None:
    value = configuration[name]
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as error:
        raise SystemExit(
            f"invalid HTTPS origin in build configuration: {name}"
        ) from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
        or parsed.query
        or parsed.path not in ("", "/")
    ):
        raise SystemExit(f"invalid HTTPS origin in build configuration: {name}")


def require_https_url(configuration: dict[str, str], name: str) -> None:
    value = configuration[name]
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as error:
        raise SystemExit(
            f"invalid HTTPS URL in build configuration: {name}"
        ) from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise SystemExit(f"invalid HTTPS URL in build configuration: {name}")


def validate(configuration: dict[str, str], profile: str) -> None:
    reject_control_characters(configuration)

    require_pattern(configuration, "PROJECT_ID", PROJECT_PATTERN)
    require_pattern(configuration, "REGION", r"[a-z]+-[a-z0-9]+[0-9]")
    require_pattern(configuration, "AR_REPOSITORY", r"[a-z0-9][a-z0-9._-]{0,126}")
    require_pattern(configuration, "IMAGE_NAME", r"[a-z0-9][a-z0-9._-]{0,126}")
    require_pattern(configuration, "ENCLAVE_KMS_PROJECT", PROJECT_PATTERN)
    require_pattern(configuration, "VERTEX_PROJECT", PROJECT_PATTERN)
    require_pattern(configuration, "ENCLAVE_RUN_SA_EMAIL", SERVICE_ACCOUNT_PATTERN)
    require_pattern(
        configuration,
        "ENCLAVE_ATTEST_STS_AUDIENCE",
        r"//iam\.googleapis\.com/projects/[0-9]+/locations/global/"
        r"workloadIdentityPools/[A-Za-z0-9._-]+/providers/[A-Za-z0-9._-]+",
    )
    for name in (
        "GOOGLE_DESKTOP_CLIENT_ID",
        "GOOGLE_IOS_CLIENT_ID",
        "GOOGLE_WEB_CLIENT_ID",
    ):
        require_pattern(configuration, name, r"[A-Za-z0-9._-]+\.apps\.googleusercontent\.com")
    if configuration.get("APPLE_TEAM_ID"):
        require_pattern(configuration, "APPLE_TEAM_ID", r"[A-Za-z0-9]{10}")
        require_pattern(configuration, "APPLE_KEY_ID", r"[A-Za-z0-9]{10}")
        require_pattern(configuration, "APPLE_IOS_CLIENT_ID", r"com\.kioku\.ios")
        require_pattern(configuration, "APPLE_MACOS_CLIENT_ID", r"com\.kiokuu\.app")
        require_pattern(configuration, "APPLE_WEB_CLIENT_ID", r"com\.kiokuu\.web")
    if configuration.get("APNS_TEAM_ID"):
        require_pattern(configuration, "APNS_TEAM_ID", r"[A-Za-z0-9]{10}")
        require_pattern(configuration, "APNS_PRODUCTION_KEY_ID", r"[A-Za-z0-9]{10}")
        require_pattern(configuration, "APNS_SANDBOX_KEY_ID", r"[A-Za-z0-9]{10}")
    require_pattern(configuration, "REVIEWER_AUTH_API_KEY", r"[A-Za-z0-9_-]{20,256}")
    require_pattern(configuration, "REVIEWER_AUTH_UID", r"[A-Za-z0-9_-]{1,128}")
    require_pattern(configuration, "REVIEWER_AUTH_EMAIL", EMAIL_PATTERN)
    for name in ("ENCLAVE_KMS_LOCATION", "VERTEX_LOCATION"):
        require_pattern(configuration, name, r"[a-z0-9][a-z0-9-]{0,62}")
    for name in ("ENCLAVE_KMS_KEY_RING", "ENCLAVE_KMS_KEY"):
        require_pattern(configuration, name, r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
    for name in (
        "ENCLAVE_GCS_BUCKET",
        "ENCLAVE_GCS_MEDIA_BUCKET",
        "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET",
    ):
        require_pattern(configuration, name, r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]")
    if (
        configuration["ENCLAVE_GCS_LEGACY_MEDIA_BUCKET"]
        != configuration["ENCLAVE_GCS_BUCKET"]
    ):
        raise SystemExit(
            "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET must exactly match ENCLAVE_GCS_BUCKET "
            "for the Phase-0 dual-media migration"
        )
    require_pattern(configuration, "VERTEX_MODEL", r"[A-Za-z0-9._:-]{1,128}")

    for name in (
        "ENCLAVE_AUDIENCE",
        "BASE_URL",
        "WEB_ORIGIN",
        "BILLING_SERVICE_URL",
        "BILLING_SERVICE_AUDIENCE",
    ):
        require_https_origin(configuration, name)
    require_https_url(configuration, "ENCLAVE_ACME_DIRECTORY")

    if configuration["ENCLAVE_ACME"] != "1":
        raise SystemExit("ENCLAVE_ACME must be 1 for an enclave image")
    if not re.fullmatch(rf"mailto:{EMAIL_PATTERN}", configuration["ENCLAVE_ACME_CONTACT"]):
        raise SystemExit("invalid format for build configuration: ENCLAVE_ACME_CONTACT")

    if not re.fullmatch(r"[1-9][0-9]{0,6}", configuration["SIGNUP_LIMIT_PER_DAY"]):
        raise SystemExit("invalid format for build configuration: SIGNUP_LIMIT_PER_DAY")

    admin_ids = [value.strip() for value in configuration["ADMIN_USER_IDS"].split(",")]
    if not admin_ids or any(
        not re.fullmatch(r"[0-9A-Fa-f-]{36}", value) for value in admin_ids
    ):
        raise SystemExit("invalid format for build configuration: ADMIN_USER_IDS")

    if configuration["BILLING_SERVICE_AUDIENCE"].rstrip("/") != configuration[
        "BILLING_SERVICE_URL"
    ].rstrip("/"):
        raise SystemExit(
            "BILLING_SERVICE_AUDIENCE must exactly match BILLING_SERVICE_URL"
        )
    if configuration["BILLING_ENFORCEMENT_MODE"] not in ("shadow", "enforce"):
        raise SystemExit(
            "BILLING_ENFORCEMENT_MODE must be either shadow or enforce"
        )
def selected_configuration(
    profile: str,
    environment: dict[str, str],
    *,
    source_ref: str,
    probe_config_path: Path,
    shadow_runtime_config_path: Path,
) -> dict[str, str]:
    prefix = profile.upper()
    configuration = {
        name: require_value(environment, name) for name in SHARED_KEYS
    }
    for name in PROFILE_KEYS:
        source_name = f"{prefix}_{name}"
        configuration[name] = require_value(environment, source_name)
    try:
        probe_config = select_probe_config(
            load_probe_config(probe_config_path),
            profile=profile,
            source_ref=source_ref,
        )
    except ProbeConfigError as error:
        raise SystemExit(str(error)) from error
    configuration.update(probe_config.as_environment())
    try:
        shadow_runtime_config = select_shadow_runtime_config(
            load_shadow_runtime_config(shadow_runtime_config_path),
            profile=profile,
            source_ref=source_ref,
        )
    except ShadowRuntimeConfigError as error:
        raise SystemExit(str(error)) from error
    configuration.update(shadow_runtime_config.as_environment())
    for group in OPTIONAL_PROFILE_GROUPS:
        values = {
            name: environment.get(f"{prefix}_{name}", "") for name in group
        }
        if any(values.values()) and not all(values.values()):
            missing = ", ".join(
                f"{prefix}_{name}" for name, value in values.items() if not value
            )
            raise SystemExit(
                "incomplete optional build configuration group; missing: " + missing
            )
        configuration.update(values)
    if profile == "production" and not configuration.get("APNS_TEAM_ID"):
        raise SystemExit(
            "missing required production build configuration: "
            "PRODUCTION_APNS_TEAM_ID, PRODUCTION_APNS_PRODUCTION_KEY_ID, "
            "PRODUCTION_APNS_SANDBOX_KEY_ID"
        )
    validate(configuration, profile)
    return configuration


def write_private_environment(
    path: Path, profile: str, configuration: dict[str, str]
) -> None:
    lines = [f"KIOKU_BUILD_PROFILE={profile}\n"]
    lines.extend(f"{name}={value}\n" for name, value in configuration.items())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.writelines(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("production", "evaluation"), required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument(
        "--archive-witness-probe-config",
        type=Path,
        default=Path("config/archive-witness-probe.json"),
    )
    parser.add_argument(
        "--archive-v3-shadow-runtime-config",
        type=Path,
        default=Path("config/archive-v3-shadow-runtime.json"),
    )
    parser.add_argument(
        "--output-env",
        type=Path,
        help="create a mode-0600 diagnostic environment file; omit to validate only",
    )
    arguments = parser.parse_args()

    environment = dict(os.environ)
    configuration = selected_configuration(
        arguments.profile,
        environment,
        source_ref=arguments.source_ref,
        probe_config_path=arguments.archive_witness_probe_config,
        shadow_runtime_config_path=arguments.archive_v3_shadow_runtime_config,
    )
    if arguments.output_env is not None:
        write_private_environment(arguments.output_env, arguments.profile, configuration)


if __name__ == "__main__":
    main()
