#!/usr/bin/env python3
"""Migrate the deployed enclave image configuration to a local private file.

The former hosted workflow combined repository variables and secrets into Docker
environment values. GitHub does not allow secret values to be read back, so the
safe cutover source is the immutable, currently deployed image. Current images
store the allowlisted values in ``/kioku-config`` instead of Docker's environment
metadata. This tool copies only that file from an exact image digest without
starting the image, using a temporary registry credential, then maps the reviewed
production fields, validates them with the canonical selector, and creates a new
external mode-0600 operator file without printing any value.
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
BAKED_CONFIG_PATH = "/kioku-config"
MAX_BAKED_CONFIG_BYTES = 256 * 1024
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
    "ENCLAVE_GCS_MEDIA_BUCKET": "GCS_MEDIA_BUCKET",
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


def read_baked_configuration(path: Path) -> dict[str, str]:
    """Read one bounded, regular stopped-container copy without following links."""

    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise BootstrapError("deployed image did not contain the baked configuration") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_size <= 0
        or metadata.st_size > MAX_BAKED_CONFIG_BYTES
    ):
        raise BootstrapError("deployed image baked configuration was not a bounded regular file")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BootstrapError("could not safely open the deployed image configuration") from error
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or (opened.st_dev, opened.st_ino, opened.st_size)
            != (metadata.st_dev, metadata.st_ino, metadata.st_size)
        ):
            raise BootstrapError("deployed image configuration changed while it was opened")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            content = handle.read(MAX_BAKED_CONFIG_BYTES + 1)
        after = os.fstat(descriptor)
        if (
            len(content) != opened.st_size
            or len(content) > MAX_BAKED_CONFIG_BYTES
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            raise BootstrapError("deployed image configuration changed while it was read")
    finally:
        os.close(descriptor)

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BootstrapError("deployed image configuration was not UTF-8 text") from error
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise BootstrapError("deployed image configuration was malformed")
    entries = text[:-1].split("\n")
    if not entries or any(not entry for entry in entries):
        raise BootstrapError("deployed image configuration was malformed")
    return parse_deployed_entries(entries)


def deployed_environment(image: str, registry: str) -> dict[str, str]:
    """Extract the baked environment file from an immutable image without executing it."""

    image_registry, _ = image_coordinates(image)
    if registry != image_registry:
        raise BootstrapError("registry does not match the digest-qualified deployed image")

    for executable in ("gcloud", "docker"):
        if shutil.which(executable) is None:
            raise BootstrapError(f"required command not found: {executable}")

    endpoint_result = subprocess.run(
        [
            "docker",
            "context",
            "inspect",
            "--format",
            "{{json .Endpoints.docker.Host}}",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        endpoint = json.loads(endpoint_result.stdout)
    except json.JSONDecodeError as error:
        raise BootstrapError("could not resolve the active local Docker endpoint") from error
    if (
        endpoint_result.returncode
        or not isinstance(endpoint, str)
        or not endpoint
        or len(endpoint) > 4096
        or any(character.isspace() or ord(character) < 32 for character in endpoint)
        or not endpoint.startswith("unix:///")
        or any(character in endpoint for character in "?#")
    ):
        raise BootstrapError("could not resolve a local Unix-socket Docker endpoint")

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

    with tempfile.TemporaryDirectory(prefix="kioku-image-bootstrap-") as temporary:
        private_root = Path(temporary)
        private_root.chmod(0o700)
        config = private_root / "registry-auth"
        config.mkdir(mode=0o700)
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
        extraction = private_root / "extracted"
        extraction.mkdir(mode=0o700)
        docker = ["docker", "--config", str(config), "--host", endpoint]
        pull_result = subprocess.run(
            [
                *docker,
                "pull",
                "--platform",
                "linux/amd64",
                image,
            ],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if pull_result.returncode:
            raise BootstrapError("could not pull the immutable deployed image")

        create_result = subprocess.run(
            [*docker, "create", "--platform", "linux/amd64", image],
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        container_id = create_result.stdout.strip()
        if create_result.returncode or not re.fullmatch(r"[0-9a-f]{64}", container_id):
            raise BootstrapError("could not create a stopped container from the deployed image")

        operation_error: BootstrapError | None = None
        result: dict[str, str] | None = None
        try:
            destination = extraction / BAKED_CONFIG_PATH.removeprefix("/")
            copy_result = subprocess.run(
                [*docker, "cp", f"{container_id}:{BAKED_CONFIG_PATH}", str(destination)],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if copy_result.returncode:
                raise BootstrapError("could not copy the immutable deployed image configuration")
            result = read_baked_configuration(destination)
        except BootstrapError as error:
            operation_error = error
        finally:
            removal = subprocess.run(
                [*docker, "rm", "--force", container_id],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if removal.returncode:
                raise BootstrapError(
                    f"temporary stopped-container cleanup failed for exact id {container_id}"
                ) from operation_error
        if operation_error is not None:
            raise operation_error
        if result is None:
            raise BootstrapError("deployed image configuration extraction did not complete")
        return result


def parse_deployed_entries(entries: object) -> dict[str, str]:
    if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
        raise BootstrapError("deployed image configuration was malformed")

    result: dict[str, str] = {}
    for entry in entries:
        if "=" not in entry:
            raise BootstrapError("deployed image configuration contained a malformed entry")
        name, value = entry.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", name) or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise BootstrapError("deployed image configuration contained a malformed entry")
        if name in result:
            raise BootstrapError("deployed image configuration contained a duplicate name")
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
