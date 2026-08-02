#!/usr/bin/env python3
"""Select one complete enclave image configuration without cross-profile fallback."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
from urllib.parse import urlsplit


SHARED_KEYS = (
    "PROJECT_ID",
    "REGION",
    "AR_REPOSITORY",
    "IMAGE_NAME",
)

AUTHENTICATION_KEYS = (
    "GCP_WIF_PROVIDER",
    "GCP_SERVICE_ACCOUNT",
)

PROFILE_KEYS = (
    "ENCLAVE_KMS_PROJECT",
    "ENCLAVE_KMS_LOCATION",
    "ENCLAVE_KMS_KEY_RING",
    "ENCLAVE_KMS_KEY",
    "ENCLAVE_GCS_BUCKET",
    "ENCLAVE_GCS_MEDIA_BUCKET",
    "ENCLAVE_RUN_SA_EMAIL",
    "ENCLAVE_AUDIENCE",
    "ENCLAVE_ATTEST_STS_AUDIENCE",
    "GOOGLE_DESKTOP_CLIENT_ID",
    "GOOGLE_IOS_CLIENT_ID",
    "GOOGLE_WEB_CLIENT_ID",
    "ALLOWED_EMAILS",
    "BASE_URL",
    "WEB_ORIGIN",
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
        raise SystemExit(f"missing required repository configuration: {name}")
    return value


def reject_control_characters(configuration: dict[str, str]) -> None:
    for name, value in configuration.items():
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise SystemExit(f"control character in repository configuration: {name}")


def require_pattern(configuration: dict[str, str], name: str, pattern: str) -> None:
    if not re.fullmatch(pattern, configuration[name]):
        raise SystemExit(f"invalid format for repository configuration: {name}")


def require_https_origin(configuration: dict[str, str], name: str) -> None:
    value = configuration[name]
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as error:
        raise SystemExit(
            f"invalid HTTPS origin in repository configuration: {name}"
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
        raise SystemExit(f"invalid HTTPS origin in repository configuration: {name}")


def require_https_url(configuration: dict[str, str], name: str) -> None:
    value = configuration[name]
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as error:
        raise SystemExit(
            f"invalid HTTPS URL in repository configuration: {name}"
        ) from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise SystemExit(f"invalid HTTPS URL in repository configuration: {name}")


def validate(configuration: dict[str, str]) -> None:
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
    require_pattern(configuration, "REVIEWER_AUTH_API_KEY", r"[A-Za-z0-9_-]{20,256}")
    require_pattern(configuration, "REVIEWER_AUTH_UID", r"[A-Za-z0-9_-]{1,128}")
    require_pattern(configuration, "REVIEWER_AUTH_EMAIL", EMAIL_PATTERN)
    for name in ("ENCLAVE_KMS_LOCATION", "VERTEX_LOCATION"):
        require_pattern(configuration, name, r"[a-z0-9][a-z0-9-]{0,62}")
    for name in ("ENCLAVE_KMS_KEY_RING", "ENCLAVE_KMS_KEY"):
        require_pattern(configuration, name, r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")
    for name in ("ENCLAVE_GCS_BUCKET", "ENCLAVE_GCS_MEDIA_BUCKET"):
        require_pattern(configuration, name, r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]")
    require_pattern(
        configuration, "VERTEX_MODEL", r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}"
    )

    for name in ("ENCLAVE_AUDIENCE", "BASE_URL", "WEB_ORIGIN"):
        require_https_origin(configuration, name)
    require_https_url(configuration, "ENCLAVE_ACME_DIRECTORY")

    if configuration["ENCLAVE_ACME"] != "1":
        raise SystemExit("ENCLAVE_ACME must be 1 for an enclave image")
    if not re.fullmatch(rf"mailto:{EMAIL_PATTERN}", configuration["ENCLAVE_ACME_CONTACT"]):
        raise SystemExit("invalid format for repository configuration: ENCLAVE_ACME_CONTACT")

    emails = [email.strip() for email in configuration["ALLOWED_EMAILS"].split(",")]
    if (
        not emails
        or any(email == "*" for email in emails)
        or any(not re.fullmatch(EMAIL_PATTERN, email) for email in emails)
    ):
        raise SystemExit("invalid format for repository configuration: ALLOWED_EMAILS")


def selected_configuration(profile: str, environment: dict[str, str]) -> dict[str, str]:
    prefix = profile.upper()
    configuration = {
        name: require_value(environment, name) for name in SHARED_KEYS
    }
    for name in PROFILE_KEYS:
        source_name = f"{prefix}_{name}"
        configuration[name] = require_value(environment, source_name)
    validate(configuration)
    return configuration


def validate_authentication(environment: dict[str, str]) -> None:
    authentication = {
        name: require_value(environment, name) for name in AUTHENTICATION_KEYS
    }
    reject_control_characters(authentication)
    require_pattern(
        authentication,
        "GCP_WIF_PROVIDER",
        r"projects/[0-9]+/locations/global/workloadIdentityPools/"
        r"[A-Za-z0-9._-]+/providers/[A-Za-z0-9._-]+",
    )
    require_pattern(
        authentication, "GCP_SERVICE_ACCOUNT", SERVICE_ACCOUNT_PATTERN
    )


def write_github_environment(
    path: Path, profile: str, configuration: dict[str, str]
) -> None:
    # Validation rejects line breaks and other controls before this append. That
    # keeps every selected value confined to its own GITHUB_ENV assignment.
    lines = [f"KIOKU_BUILD_PROFILE={profile}\n"]
    lines.extend(f"{name}={value}\n" for name, value in configuration.items())
    with path.open("a", encoding="utf-8") as handle:
        handle.writelines(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=("production", "evaluation"), required=True)
    parser.add_argument("--github-env", type=Path, required=True)
    arguments = parser.parse_args()

    environment = dict(os.environ)
    configuration = selected_configuration(arguments.profile, environment)
    validate_authentication(environment)
    write_github_environment(arguments.github_env, arguments.profile, configuration)


if __name__ == "__main__":
    main()
