#!/usr/bin/env python3
"""Migrate the deployed enclave image configuration to a local private file.

The former hosted workflow combined repository variables and secrets into Docker
environment values. GitHub does not allow secret values to be read back, so the
safe cutover source is the immutable, currently deployed image. This tool reads
only that image's configuration through a temporary registry credential, maps
the reviewed production fields, validates them with the canonical selector, and
creates a new external mode-0600 operator file without printing any value.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

from select_build_configuration import (
    OPTIONAL_PROFILE_GROUPS,
    PROFILE_KEYS,
    SERVICE_ACCOUNT_PATTERN,
    SHARED_KEYS,
    selected_configuration,
)


ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(
    r"(?P<location>[a-z][a-z0-9-]+)-docker\.pkg\.dev/"
    r"(?P<project>[a-z][a-z0-9-]{4,28}[a-z0-9])/"
    r"(?P<repository>[a-z0-9][a-z0-9._-]{0,126})/"
    r"(?P<name>[a-z0-9][a-z0-9._-]{0,126})@sha256:[0-9a-f]{64}\Z"
)
IMAGE_ENVIRONMENT_NAMES = {
    "ENCLAVE_KMS_PROJECT": "KMS_PROJECT",
    "ENCLAVE_KMS_LOCATION": "KMS_LOCATION",
    "ENCLAVE_KMS_KEY_RING": "KMS_KEY_RING",
    "ENCLAVE_KMS_KEY": "KMS_KEY",
    "ENCLAVE_GCS_BUCKET": "GCS_BUCKET",
    "ENCLAVE_GCS_MEDIA_BUCKET": "GCS_MEDIA_BUCKET",
    "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET": "GCS_LEGACY_MEDIA_BUCKET",
    "ENCLAVE_RUN_SA_EMAIL": "RUN_SA_EMAIL",
    "ENCLAVE_ATTEST_STS_AUDIENCE": "ATTEST_STS_AUDIENCE",
}


class BootstrapError(RuntimeError):
    pass


def image_coordinates(image: str) -> tuple[str, dict[str, str]]:
    match = IMAGE.fullmatch(image)
    if match is None:
        raise BootstrapError("--image must be an exact Artifact Registry sha256 reference")
    values = match.groupdict()
    registry = f"{values['location']}-docker.pkg.dev"
    return registry, {
        "PROJECT_ID": values["project"],
        "REGION": values["location"],
        "AR_REPOSITORY": values["repository"],
        "IMAGE_NAME": values["name"],
    }


def deployed_environment(image: str, registry: str) -> dict[str, str]:
    for executable in ("gcloud", "docker", "docker-buildx"):
        if shutil.which(executable) is None:
            raise BootstrapError(f"required command not found: {executable}")

    token_result = subprocess.run(
        ["gcloud", "auth", "print-access-token"],
        text=True,
        capture_output=True,
        check=False,
    )
    token = token_result.stdout.strip()
    if token_result.returncode or not (20 <= len(token) <= 8192) or any(
        character.isspace() for character in token
    ):
        raise BootstrapError("the active local gcloud identity could not mint a registry token")

    with tempfile.TemporaryDirectory(prefix="kioku-registry-auth-") as temporary:
        config = Path(temporary)
        config.chmod(0o700)
        login = subprocess.run(
            [
                "docker",
                "--config",
                str(config),
                "login",
                registry,
                "--username",
                "oauth2accesstoken",
                "--password-stdin",
            ],
            input=token + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        token = ""
        if login.returncode:
            raise BootstrapError("temporary Artifact Registry login failed")
        environment = dict(os.environ)
        environment["DOCKER_CONFIG"] = str(config)
        inspection = subprocess.run(
            [
                "docker-buildx",
                "imagetools",
                "inspect",
                "--format",
                "{{json .Image.Config.Env}}",
                image,
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
    if inspection.returncode:
        raise BootstrapError("could not inspect the immutable deployed image configuration")
    try:
        entries = json.loads(inspection.stdout)
    except json.JSONDecodeError as error:
        raise BootstrapError("deployed image configuration was malformed") from error

    return parse_deployed_entries(entries)


def parse_deployed_entries(entries: object) -> dict[str, str]:
    if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
        raise BootstrapError("deployed image environment was malformed")

    result: dict[str, str] = {}
    for entry in entries:
        if "=" not in entry:
            raise BootstrapError("deployed image environment contained a malformed entry")
        name, value = entry.split("=", 1)
        if name in result:
            raise BootstrapError("deployed image environment contained a duplicate name")
        result[name] = value
    if result.get("KIOKU_BUILD_PROFILE") != "production":
        raise BootstrapError("the selected deployed image is not a production build")
    return result


def operator_values(
    coordinates: dict[str, str], image_environment: dict[str, str], builder: str
) -> dict[str, str]:
    if not re.fullmatch(SERVICE_ACCOUNT_PATTERN, builder):
        raise BootstrapError("--builder-service-account must be a service account email")
    values = dict(coordinates)
    for name in PROFILE_KEYS:
        image_name = IMAGE_ENVIRONMENT_NAMES.get(name, name)
        value = image_environment.get(image_name, "")
        if not value:
            raise BootstrapError(f"deployed image is missing required configuration: {image_name}")
        values[f"PRODUCTION_{name}"] = value
    for group in OPTIONAL_PROFILE_GROUPS:
        group_values = {name: image_environment.get(name, "") for name in group}
        if any(group_values.values()) and not all(group_values.values()):
            raise BootstrapError("deployed image has an incomplete optional configuration group")
        for name, value in group_values.items():
            if value:
                values[f"PRODUCTION_{name}"] = value
    values["LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT"] = builder

    try:
        selected_configuration(
            "production",
            values,
            # This migration validates the deployed image's ordinary
            # production coordinates. Release-only profiles are selected only
            # while building their exact signed tag, never from an ambient
            # checkout name such as HEAD.
            source_ref="main",
            probe_config_path=ROOT / "config/archive-witness-probe.json",
            shadow_runtime_config_path=ROOT / "config/archive-v3-shadow-runtime.json",
        )
    except SystemExit as error:
        raise BootstrapError("deployed image configuration failed current validation") from error
    return values


def write_private(path: Path, values: dict[str, str]) -> None:
    absolute = path.expanduser().absolute()
    try:
        absolute.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise BootstrapError("local operator configuration must live outside the repository")

    parent = absolute.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_metadata = os.lstat(parent)
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
        or parent.resolve(strict=True) != parent.absolute()
    ):
        raise BootstrapError("configuration directory must be private, current-user-owned, and symlink-free")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(absolute, flags, 0o600)
    except FileExistsError as error:
        raise BootstrapError("refusing to overwrite an existing operator configuration") from error
    ordered_names = [
        *SHARED_KEYS,
        *(f"PRODUCTION_{name}" for name in PROFILE_KEYS),
        *(
            f"PRODUCTION_{name}"
            for group in OPTIONAL_PROFILE_GROUPS
            for name in group
            if f"PRODUCTION_{name}" in values
        ),
        "LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT",
    ]
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.writelines(f"{name}={values[name]}\n" for name in ordered_names)
    except Exception:
        absolute.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="currently deployed digest-qualified image")
    parser.add_argument("--output", type=Path, required=True, help="new external mode-0600 file")
    parser.add_argument(
        "--builder-service-account",
        help="push-only local Artifact Registry identity (defaults to kioku-enclave-ci in the image project)",
    )
    arguments = parser.parse_args()
    try:
        registry, coordinates = image_coordinates(arguments.image)
        builder = arguments.builder_service_account or (
            f"kioku-enclave-ci@{coordinates['PROJECT_ID']}.iam.gserviceaccount.com"
        )
        environment = deployed_environment(arguments.image, registry)
        values = operator_values(coordinates, environment, builder)
        write_private(arguments.output, values)
        print(f"local operator configuration created at {arguments.output.expanduser().absolute()}")
        print("no configuration value was printed; review the private file before first use")
        return 0
    except BootstrapError as error:
        print(f"local configuration bootstrap refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
