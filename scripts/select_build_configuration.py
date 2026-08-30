#!/usr/bin/env python3
"""Select one complete PostgreSQL-authoritative enclave image configuration."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


SHARED_KEYS = ("PROJECT_ID", "REGION", "AR_REPOSITORY", "IMAGE_NAME")

PROFILE_KEYS = (
    "ENCLAVE_KMS_PROJECT",
    "ENCLAVE_KMS_LOCATION",
    "ENCLAVE_KMS_KEY_RING",
    "ENCLAVE_KMS_KEY",
    "ENCLAVE_GCS_MEDIA_BUCKET",
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
)

OPTIONAL_PROFILE_GROUPS = (
    (
        "APPLE_TEAM_ID",
        "APPLE_KEY_ID",
        "APPLE_IOS_CLIENT_ID",
        "APPLE_MACOS_CLIENT_ID",
        "APPLE_WEB_CLIENT_ID",
    ),
    ("APNS_TEAM_ID", "APNS_PRODUCTION_KEY_ID", "APNS_SANDBOX_KEY_ID"),
)

PROJECT_PATTERN = r"[a-z][a-z0-9-]{4,28}[a-z0-9]"
SERVICE_ACCOUNT_PATTERN = (
    r"[a-z0-9][a-z0-9-]{4,28}[a-z0-9]@"
    + PROJECT_PATTERN
    + r"\.iam\.gserviceaccount\.com"
)
EMAIL_PATTERN = r"[^@,\s]+@[^@,\s]+"
RELEASE_TAG_PATTERN = (
    r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)(?:[.-][0-9A-Za-z.-]+)?"
)


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
        raise SystemExit(f"invalid HTTPS origin in build configuration: {name}") from error
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


def validate(configuration: dict[str, str], profile: str, source_ref: str) -> None:
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
    require_pattern(
        configuration,
        "ENCLAVE_GCS_MEDIA_BUCKET",
        r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]",
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

    if configuration["POSTGRES_MAX_CONNECTIONS"] != "12":
        raise SystemExit("POSTGRES_MAX_CONNECTIONS must match the reviewed fleet pool budget")
    if configuration["HEALTH_PORT"] != "8081":
        raise SystemExit("HEALTH_PORT must be the reviewed health-only port")
    if configuration["DRAIN_TIMEOUT_SECONDS"] != "105":
        raise SystemExit("DRAIN_TIMEOUT_SECONDS must fit the Confidential Space SIGTERM window")
    if configuration["ENCLAVE_TLS"] != "1":
        raise SystemExit("PostgreSQL fleet images require shared TLS")
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,6})", configuration["SIGNUP_LIMIT_PER_DAY"]):
        raise SystemExit("invalid format for build configuration: SIGNUP_LIMIT_PER_DAY")

    admin_ids = [value.strip() for value in configuration["ADMIN_USER_IDS"].split(",")]
    if not admin_ids or any(not re.fullmatch(r"[0-9A-Fa-f-]{36}", value) for value in admin_ids):
        raise SystemExit("invalid format for build configuration: ADMIN_USER_IDS")
    if configuration["BILLING_SERVICE_AUDIENCE"].rstrip("/") != configuration[
        "BILLING_SERVICE_URL"
    ].rstrip("/"):
        raise SystemExit("BILLING_SERVICE_AUDIENCE must exactly match BILLING_SERVICE_URL")
    if configuration["BILLING_ENFORCEMENT_MODE"] not in ("shadow", "enforce"):
        raise SystemExit("BILLING_ENFORCEMENT_MODE must be either shadow or enforce")
    if configuration["PASSWORD_AUTH_MODE"] != "off":
        raise SystemExit("release images must keep general password authentication off")
    if configuration["PASSWORD_AUTH_API_KEY"]:
        raise SystemExit("release images must not bake a general password authentication API key")
    if configuration["PASSWORD_AUTH_PROJECT_ID"] or configuration["PASSWORD_AUTH_TENANT_ID"]:
        raise SystemExit("release images must not bake general password identity coordinates")
    if profile == "production" and not configuration.get("APNS_TEAM_ID"):
        raise SystemExit(
            "missing required production build configuration: PRODUCTION_APNS_TEAM_ID, "
            "PRODUCTION_APNS_PRODUCTION_KEY_ID, PRODUCTION_APNS_SANDBOX_KEY_ID"
        )
    tag = source_ref.removeprefix("refs/tags/")
    if tag.startswith("v") and not re.fullmatch(RELEASE_TAG_PATTERN, tag):
        raise SystemExit("release source_ref is not a canonical version tag")


def selected_configuration(
    profile: str,
    environment: dict[str, str],
    *,
    source_ref: str,
) -> dict[str, str]:
    prefix = profile.upper()
    configuration = {name: require_value(environment, name) for name in SHARED_KEYS}
    for name in PROFILE_KEYS:
        configuration[name] = require_value(environment, f"{prefix}_{name}")
    for group in OPTIONAL_PROFILE_GROUPS:
        values = {name: environment.get(f"{prefix}_{name}", "") for name in group}
        if any(values.values()) and not all(values.values()):
            missing = ", ".join(
                f"{prefix}_{name}" for name, value in values.items() if not value
            )
            raise SystemExit("incomplete optional build configuration group; missing: " + missing)
        configuration.update(values)
    # These fleet invariants are reviewed source, not operator-selectable modes.
    # Serving replicas verify the schema unconditionally in Rust and never run DDL.
    configuration.update(
        {
            "POSTGRES_MAX_CONNECTIONS": "12",
            "HEALTH_PORT": "8081",
            "DRAIN_TIMEOUT_SECONDS": "105",
            "ENCLAVE_TLS": "1",
            # General password auth remains a source-reviewed release gate. It
            # is intentionally not an operator/profile variable until the
            # client-parity, upstream-abuse, and lifecycle gates are complete.
            "PASSWORD_AUTH_MODE": "off",
            "PASSWORD_AUTH_API_KEY": "",
            "PASSWORD_AUTH_PROJECT_ID": "",
            "PASSWORD_AUTH_TENANT_ID": "",
        }
    )
    validate(configuration, profile, source_ref)
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
        "--output-env",
        type=Path,
        help="create a mode-0600 diagnostic environment file; omit to validate only",
    )
    arguments = parser.parse_args()
    configuration = selected_configuration(
        arguments.profile, dict(os.environ), source_ref=arguments.source_ref
    )
    if arguments.output_env is not None:
        write_private_environment(arguments.output_env, arguments.profile, configuration)


if __name__ == "__main__":
    main()
