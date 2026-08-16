#!/usr/bin/env python3
"""Fail-closed local enclave verification, image build, scan, and push pipeline.

This intentionally replaces the executable portions of the former hosted build
job.  It accepts a mode-0600 operator configuration file rather than sourcing
shell, performs all untrusted build and scan work before acquiring cloud
credentials, and leaves signing/release publication to a separate operator
step.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse

from select_build_configuration import (
    OPTIONAL_PROFILE_GROUPS,
    PROFILE_KEYS,
    SERVICE_ACCOUNT_PATTERN,
    SHARED_KEYS,
    selected_configuration,
)


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_SBOM_PACKAGES = {
    "kioku-enclave",
    "jsonwebtoken",
    "rusqlite",
    "sqlite-vec",
    "onig",
}
SYFT_VERSION = "1.49.0"
GRYPE_VERSION = "0.116.0"
GCLOUD_VERSION = "580.0.0"
CARGO_AUDIT_VERSION = "0.22.2"
CACHE_RESERVE_BYTES = 50 * 1024**3
SCAN_MAX_AGE_SECONDS = 24 * 60 * 60
OCI_ARTIFACT_NAME = "kioku-enclave.oci.tar"
NATIVE_DISK_PROBE_IMAGE = (
    "rust:1.97.1-slim@sha256:3b2879047d42784ca9403ad20c51ed3df361a50f1df96f5777d39b4e33aa65cd"
)
CONFIG_NAME = re.compile(r"[A-Z][A-Z0-9_]*\Z")
BUILDER_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CONFIG_SECRET_KEYS = frozenset({
    "auth", "auths", "clientsecret", "credhelpers", "credsstore",
    "identitytoken", "password", "registrytoken", "secret", "token", "username",
})
DIRECT_ENV_BASE = frozenset({
    "PATH", "HOME", "XDG_STATE_HOME", "LC_ALL", "TMPDIR", "CARGO_HOME", "RUSTUP_HOME",
})
DIRECT_ENV_TRANSPORT = frozenset({
    "KIOKU_NATIVE_BUILDER_NAME", "KIOKU_NATIVE_BUILDER_ID", "DOCKER_HOST",
    "DOCKER_SSH_KNOWN_HOSTS", "DOCKER_SSH_HOST_KEY_SHA256", "DOCKER_SSH_COMMAND",
    "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_BUILDER_CA_SHA256", "SSH_AUTH_SOCK",
})
DIRECT_CREDENTIAL_ENV = frozenset({
    "GOOGLE_APPLICATION_CREDENTIALS", "DOCKER_AUTH_CONFIG", "GH_TOKEN", "GITHUB_TOKEN",
    "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY", "KIOKU_RELEASE_GITHUB_TOKEN",
    "KIOKU_RELEASE_GCP_READONLY_SERVICE_ACCOUNT", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_CLIENT_ID", "AZURE_TENANT_ID",
})
_CHILD_ENVIRONMENT: dict[str, str] | None = None
_CLOUDSDK_CONFIG: str | None = None
OPERATOR_CONFIG_KEYS = frozenset(
    (*SHARED_KEYS, "LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT")
    + tuple(
        f"{profile}_{key}"
        for profile in ("PRODUCTION", "EVALUATION")
        for key in (*PROFILE_KEYS, *(key for group in OPTIONAL_PROFILE_GROUPS for key in group))
    )
    + tuple(
        f"{profile}_{key}"
        for profile in ("PRODUCTION", "EVALUATION")
        for key in (
            "ARCHIVE_WITNESS_SHADOW_MODE",
            "ARCHIVE_WITNESS_PROJECT_ID",
            "ARCHIVE_WITNESS_PROJECT_NUMBER",
            "ARCHIVE_WITNESS_DATABASE_ID",
        )
    )
)


class PipelineError(RuntimeError):
    """A fail-closed operator error that should not expose configuration values."""


def canonical_path(path: Path, label: str) -> Path:
    """Resolve one path while allowing macOS's canonical /var alias only."""
    try:
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise PipelineError(f"{label} has an unsafe path") from error
    if canonical != path and not (
        path.parts[:2] == ("/", "var")
        and canonical.parts[:3] == ("/", "private", "var")
        and canonical.parts[3:] == path.parts[2:]
    ):
        raise PipelineError(f"{label} has symlinked ancestry")
    return canonical


class OperatorConfigSnapshot:
    """The one stable read of the operator configuration used by a run."""

    __slots__ = ("values", "data", "sha256")

    def __init__(self, values: dict[str, str], data: bytes, sha256: str) -> None:
        self.values = values
        self.data = data
        self.sha256 = sha256


def required_free_bytes(total_bytes: int) -> int:
    """Return the larger of the absolute and proportional builder reserves."""
    return max(CACHE_RESERVE_BYTES, total_bytes // 4)


def buildx_ls_entries() -> list[dict[str, object]]:
    """Read the documented machine-readable Buildx builder listing.

    ``buildx inspect`` has no supported ``--format`` option on the versions we
    review.  ``buildx ls --format '{{json .}}'`` emits one JSON builder object
    per line, including its actual nested node records, so parsing that output
    avoids guessing at the client's default context or a human table layout.
    """
    listing = run(
        ["docker", "buildx", "ls", "--no-trunc", "--format", "{{json .}}"],
        capture=True,
    ).stdout
    entries: list[dict[str, object]] = []
    for line in listing.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as error:
            raise PipelineError("Buildx ls machine-readable output is not JSON") from error
        if not isinstance(entry, dict):
            raise PipelineError("Buildx ls machine-readable output has an invalid builder")
        entries.append(entry)
    if not entries:
        raise PipelineError("Buildx ls returned no builders")
    return entries


def buildx_builder_field(builder: dict[str, object], name: str) -> object:
    """Read Buildx's documented JSON field across CLI key casing variants."""
    return builder.get(name, builder.get(name[:1].lower() + name[1:], builder.get(name.lower())))


def selected_buildx_nodes(builder_name: str) -> list[dict[str, object]]:
    """Read exactly one selected Buildx builder and its nested node list."""
    if not BUILDER_NAME.fullmatch(builder_name):
        raise PipelineError("KIOKU_NATIVE_BUILDER_NAME is not a safe reviewed builder name")
    matches = [
        builder
        for builder in buildx_ls_entries()
        if buildx_builder_field(builder, "Name") == builder_name
    ]
    # Buildx 0.36 can emit the same standalone remote builder twice when a
    # dedicated BUILDX_CONFIG is used alongside an isolated DOCKER_CONFIG.
    # Collapse only byte-equivalent JSON objects; conflicting duplicates stay
    # ambiguous and fail closed.
    unique_matches = {
        json.dumps(builder, sort_keys=True, separators=(",", ":")): builder
        for builder in matches
    }
    if len(unique_matches) != 1:
        raise PipelineError("Buildx ls did not return exactly one selected builder")
    nodes = buildx_builder_field(next(iter(unique_matches.values())), "Nodes")
    if not isinstance(nodes, list) or any(not isinstance(node, dict) for node in nodes):
        raise PipelineError("selected Buildx builder has an invalid node list")
    if len(nodes) != 1:
        raise PipelineError("selected Buildx builder must have exactly one node")
    return nodes


def buildx_node_field(node: dict[str, object], name: str) -> object:
    """Read Buildx's JSON field across CLI versions' key casing."""
    return node.get(name, node.get(name[:1].lower() + name[1:], node.get(name.lower())))


def buildx_node_platforms(node: dict[str, object]) -> set[str]:
    platforms = buildx_node_field(node, "Platforms")
    if isinstance(platforms, list):
        return {value.strip() for value in platforms if isinstance(value, str)}
    if isinstance(platforms, str):
        return {value.strip() for value in platforms.split(",")}
    return set()


def known_hosts_has_fingerprint(payload: bytes, endpoint: str, expected: str) -> bool:
    """Bind the pin to the key for the endpoint, not arbitrary file text."""
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme != "ssh" or not parsed.hostname:
        return False
    hostnames = {parsed.hostname}
    if parsed.port is not None:
        hostnames.add(f"[{parsed.hostname}]:{parsed.port}")
    normalized = expected.rstrip("=")
    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(b"#"):
            continue
        fields = line.split()
        offset = 1 if fields and fields[0].startswith(b"@") else 0
        if len(fields) < offset + 3:
            continue
        try:
            names = fields[offset].decode("ascii").split(",")
            if not hostnames.intersection(names):
                continue
            key = base64.b64decode(fields[offset + 2], validate=True)
        except (UnicodeDecodeError, ValueError):
            continue
        actual = "SHA256:" + base64.b64encode(hashlib.sha256(key).digest()).decode("ascii").rstrip("=")
        if actual == normalized:
            return True
    return False


def native_builder_identity() -> dict[str, str] | None:
    """Return the reviewed identity of the one selected Buildx worker."""
    expected_builder_name = os.environ.get("KIOKU_NATIVE_BUILDER_NAME", "")
    if not BUILDER_NAME.fullmatch(expected_builder_name):
        return None
    try:
        nodes = selected_buildx_nodes(expected_builder_name)
    except PipelineError:
        return None
    if len(nodes) != 1:
        return None
    node = nodes[0]
    node_name = buildx_node_field(node, "Name")
    endpoint = buildx_node_field(node, "Endpoint")
    if (
        not isinstance(node_name, str)
        or not BUILDER_NAME.fullmatch(node_name)
        or buildx_node_field(node, "Status") != "running"
        or not isinstance(endpoint, str)
        or not re.fullmatch(r"(?:unix|tcp|ssh)://[^\s\x00-\x1f\x7f]+", endpoint)
        or "linux/amd64" not in buildx_node_platforms(node)
    ):
        return None
    configured_endpoint = os.environ.get("DOCKER_HOST")
    if configured_endpoint and configured_endpoint != endpoint:
        return None
    transport = endpoint.split(":", 1)[0]
    transport_pin = hashlib.sha256(endpoint.encode("utf-8")).hexdigest()
    if endpoint.startswith("ssh://"):
        known_hosts = os.environ.get("DOCKER_SSH_KNOWN_HOSTS", "")
        host_key = os.environ.get("DOCKER_SSH_HOST_KEY_SHA256", "")
        ssh_command = os.environ.get("DOCKER_SSH_COMMAND", "")
        try:
            ssh_tokens = shlex.split(ssh_command)
        except ValueError:
            ssh_tokens = []
        ssh_options = {
            option.split("=", 1)[0]: option.split("=", 1)[1]
            for index, option in enumerate(ssh_tokens)
            if index > 0 and ssh_tokens[index - 1] == "-o" and "=" in option
        }
        if (
            not re.fullmatch(r"SHA256:[A-Za-z0-9+/]+={0,2}", host_key)
            or not ssh_tokens
            or ssh_tokens[0] != "ssh"
            or ssh_options.get("StrictHostKeyChecking") != "yes"
            or ssh_options.get("UserKnownHostsFile") != known_hosts
        ):
            return None
        try:
            known_hosts_bytes = read_owned_bytes(
                Path(known_hosts), "pinned Docker known-hosts file", private=True
            )
            if not known_hosts_has_fingerprint(known_hosts_bytes, endpoint, host_key):
                return None
        except (PipelineError, OSError, UnicodeDecodeError):
            return None
        transport_pin = host_key
    elif endpoint.startswith("tcp://"):
        # A pinned CA file is not enough: Docker only enables TLS when this
        # switch is set.  Enforce it here as well as in the coordinator
        # adapter so direct invocations cannot accidentally probe an
        # unauthenticated TCP daemon.
        if os.environ.get("DOCKER_TLS_VERIFY") != "1":
            return None
        ca_hash = os.environ.get("DOCKER_BUILDER_CA_SHA256", "")
        cert_path = os.environ.get("DOCKER_CERT_PATH", "")
        if not re.fullmatch(r"[0-9a-f]{64}", ca_hash) or not cert_path:
            return None
        try:
            cert_directory = Path(cert_path)
            directory_metadata = cert_directory.lstat()
            if (
                stat.S_ISLNK(directory_metadata.st_mode)
                or not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(directory_metadata.st_mode) & 0o077
            ):
                return None
            ca = Path(cert_path) / "ca.pem"
            ca_bytes = read_owned_bytes(ca, "Docker builder CA", private=True)
            read_owned_bytes(cert_directory / "cert.pem", "Docker client certificate", private=True)
            read_owned_bytes(cert_directory / "key.pem", "Docker client key", private=True)
            if hashlib.sha256(ca_bytes).hexdigest() != ca_hash:
                return None
        except PipelineError:
            return None
        transport_pin = ca_hash
    elif not endpoint.startswith("unix://"):
        return None
    try:
        info = run(
            [
                "docker", "--host", endpoint, "info",
                "--format", "{{.ID}} {{.OSType}} {{.Architecture}}",
            ],
            capture=True,
        ).stdout.strip()
    except PipelineError:
        return None
    parts = info.split()
    if len(parts) != 3 or parts[1].lower() != "linux" or parts[2].lower() not in {"amd64", "x86_64"}:
        return None
    expected_identity = os.environ.get("KIOKU_NATIVE_BUILDER_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", expected_identity) or parts[0] != expected_identity:
        return None
    return {
        "id": parts[0],
        "name": expected_builder_name,
        "node_name": node_name,
        "endpoint": endpoint,
        "platform": "linux/amd64",
        "transport": transport,
        "transport_pin": transport_pin,
    }


def native_linux_builder() -> bool:
    """Check a probed Linux worker against the operator's reviewed identity pin."""
    return native_builder_identity() is not None


def check_builder_disk_space(builder_name: str | None = None) -> tuple[int, int, int]:
    """Probe the filesystem of the selected Buildx worker.

    A plain default-daemon container invocation would inspect whichever daemon
    is active in the client's default context, which can differ from a named
    remote Buildx worker. Instead, this uses a no-network, no-cache BuildKit
    probe bound to the exact reviewed builder name. ``df`` runs inside the pinned probe image
    on that worker, and BuildKit's plain progress output carries the report
    back to this process.  Missing names, failed probes, or ambiguous output
    all fail closed.
    """
    selected_builder = (
        builder_name
        if builder_name is not None
        else os.environ.get("KIOKU_NATIVE_BUILDER_NAME", "")
    )
    if not BUILDER_NAME.fullmatch(selected_builder):
        raise PipelineError("native disk probe requires the exact reviewed Buildx builder name")
    with tempfile.TemporaryDirectory(prefix="kioku-builder-disk-probe-") as temporary:
        context = Path(temporary)
        dockerfile = context / "Dockerfile"
        dockerfile.write_text(
            f"FROM {NATIVE_DISK_PROBE_IMAGE}\nRUN df -Pk /\n",
            encoding="ascii",
        )
        completed = run(
            [
                "docker", "buildx", "build", "--builder", selected_builder,
                "--platform", "linux/amd64", "--pull=false", "--no-cache",
                "--network=none", "--progress=plain", "--output=type=cacheonly",
                "--file", str(dockerfile), str(context),
            ],
            capture=True,
        )
    rows = []
    probe_output = "\n".join(
        value for value in (getattr(completed, "stdout", ""), getattr(completed, "stderr", "")) if value
    )
    for line in probe_output.splitlines():
        fields = line.split()
        if len(fields) < 6:
            continue
        _filesystem, blocks, _used, available, capacity, mount = fields[-6:]
        capacity_value = capacity[:-1] if capacity.endswith("%") else ""
        if (
            mount == "/"
            and blocks.isdigit()
            and available.isdigit()
            and re.fullmatch(r"[0-9]+%", capacity)
            and int(capacity_value) <= 100
        ):
            rows.append((int(available) * 1024, int(blocks) * 1024))
    if len(rows) != 1:
        raise PipelineError("named Buildx worker free-space probe returned no exact root filesystem")
    free_bytes, total_bytes = rows[0]
    reserve = required_free_bytes(total_bytes)
    if total_bytes <= 0 or free_bytes < reserve:
        raise PipelineError("named Buildx worker has insufficient free space for the bounded cache reserve")
    return free_bytes, reserve, total_bytes


def native_builder_snapshot() -> dict[str, object] | None:
    """Capture one identity/transport/disk snapshot for receipt input binding."""
    identity = native_builder_identity()
    if identity is None:
        return None
    free_bytes, reserve, total_bytes = check_builder_disk_space(str(identity["name"]))
    return {
        **identity,
        "disk_free_bytes": free_bytes,
        "disk_reserve_bytes": reserve,
        "disk_total_bytes": total_bytes,
    }


BUILDER_IDENTITY_FIELDS = (
    "id",
    "name",
    "node_name",
    "endpoint",
    "platform",
    "transport",
    "transport_pin",
)


def builder_identity_binding(snapshot: dict[str, object]) -> dict[str, object]:
    """Return the immutable worker identity portion of a builder snapshot."""
    if any(field not in snapshot for field in BUILDER_IDENTITY_FIELDS):
        raise PipelineError("builder snapshot is missing an identity binding")
    return {field: snapshot[field] for field in BUILDER_IDENTITY_FIELDS}


def reviewed_private_config_directory(
    path_value: str,
    label: str,
    *,
    tighten_owned_files: bool = False,
) -> Path:
    """Validate a dedicated Docker/Buildx directory before passing it to children."""
    path = Path(path_value)
    if not path.is_absolute() or ".." in path.parts:
        raise PipelineError(f"{label} must be an absolute path outside the repository")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PipelineError(f"{label} is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PipelineError(f"{label} must be a current-user-owned mode-0700 directory")
    canonical = canonical_path(path, label)
    path = canonical
    try:
        path.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise PipelineError(f"{label} must be outside the source repository")
    for directory, directories, files in os.walk(path, topdown=True, followlinks=False):
        parent = Path(directory)
        for name in directories:
            child = parent / name
            child_metadata = child.lstat()
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(child_metadata.st_mode) != 0o700
            ):
                raise PipelineError(f"{label} contains an unsafe directory")
        for name in files:
            child = parent / name
            child_metadata = child.lstat()
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISREG(child_metadata.st_mode)
                or child_metadata.st_uid != os.geteuid()
            ):
                raise PipelineError(f"{label} contains an unsafe file")
            if stat.S_IMODE(child_metadata.st_mode) != 0o600:
                if not tighten_owned_files:
                    raise PipelineError(f"{label} contains an unsafe file")
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                try:
                    descriptor = os.open(child, flags)
                except OSError as error:
                    raise PipelineError(f"{label} contains an unsafe file") from error
                try:
                    opened_metadata = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened_metadata.st_mode)
                        or opened_metadata.st_uid != os.geteuid()
                        or (opened_metadata.st_dev, opened_metadata.st_ino)
                        != (child_metadata.st_dev, child_metadata.st_ino)
                    ):
                        raise PipelineError(f"{label} contains an unsafe file")
                    os.fchmod(descriptor, 0o600)
                except OSError as error:
                    raise PipelineError(f"{label} contains an unsafe file") from error
                finally:
                    os.close(descriptor)
            if child.suffix.lower() != ".json" and child.name != "config.json":
                continue
            try:
                document = json.loads(
                    read_owned_bytes(child, f"{label} JSON metadata", private=True)
                )
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
                raise PipelineError(f"{label} contains invalid JSON metadata") from error

            def check(value: object) -> None:
                if isinstance(value, dict):
                    for key, nested in value.items():
                        if str(key).replace("_", "").replace("-", "").lower() in CONFIG_SECRET_KEYS:
                            raise PipelineError(f"{label} contains credential material")
                        check(nested)
                elif isinstance(value, list):
                    for nested in value:
                        check(nested)

            check(document)
    return path


def reviewed_cloud_config_directory(path_value: str) -> Path:
    """Validate the private gcloud configuration explicitly selected for a stage."""
    path = Path(path_value)
    if not path.is_absolute() or ".." in path.parts:
        raise PipelineError("CLOUDSDK_CONFIG must be an absolute path outside the repository")
    try:
        metadata = path.lstat()
    except OSError as error:
        raise PipelineError("CLOUDSDK_CONFIG is unavailable") from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PipelineError("CLOUDSDK_CONFIG must be a current-user-owned mode-0700 directory")
    canonical = canonical_path(path, "CLOUDSDK_CONFIG")
    path = canonical
    try:
        path.relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        raise PipelineError("CLOUDSDK_CONFIG must be outside the source repository")
    for directory, directories, files in os.walk(path, topdown=True, followlinks=False):
        parent = Path(directory)
        for name in directories:
            child = parent / name
            child_metadata = child.lstat()
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(child_metadata.st_mode) != 0o700
            ):
                raise PipelineError("CLOUDSDK_CONFIG contains an unsafe directory")
        for name in files:
            child = parent / name
            child_metadata = child.lstat()
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISREG(child_metadata.st_mode)
                or child_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(child_metadata.st_mode) != 0o600
            ):
                raise PipelineError("CLOUDSDK_CONFIG contains an unsafe file")
    return path


def configure_direct_child_environment(stage: str) -> None:
    """Install the direct CLI's reviewed, stage-scoped child environment."""
    global _CHILD_ENVIRONMENT, _CLOUDSDK_CONFIG
    present_credentials = sorted(
        name for name in DIRECT_CREDENTIAL_ENV if os.environ.get(name)
    )
    if present_credentials:
        raise PipelineError(
            "ambient credentials are not accepted by the local release pipeline: "
            + ", ".join(present_credentials)
        )
    if os.environ.get("DOCKER_CONTEXT"):
        raise PipelineError("DOCKER_CONTEXT is not accepted; use the reviewed Docker endpoint")
    child = {
        name: value for name, value in os.environ.items() if name in DIRECT_ENV_BASE
    }
    if stage in {"preflight", "build", "push"}:
        docker_config_value = os.environ.get("KIOKU_RELEASE_NATIVE_DOCKER_CONFIG", "")
        buildx_config_value = os.environ.get("KIOKU_RELEASE_NATIVE_BUILDX_CONFIG", "")
        if not docker_config_value or not buildx_config_value:
            raise PipelineError(
                "direct build stages require dedicated KIOKU_RELEASE_NATIVE_DOCKER_CONFIG "
                "and KIOKU_RELEASE_NATIVE_BUILDX_CONFIG directories"
            )
        docker_config = reviewed_private_config_directory(docker_config_value, "native Docker config directory")
        buildx_config = reviewed_private_config_directory(
            buildx_config_value,
            "native Buildx config directory",
            tighten_owned_files=True,
        )
        child.update({"DOCKER_CONFIG": str(docker_config), "BUILDX_CONFIG": str(buildx_config)})
        for name in DIRECT_ENV_TRANSPORT:
            if name in os.environ:
                child[name] = os.environ[name]
        endpoint = os.environ.get("DOCKER_HOST", "")
        ssh_coordinates = {
            "DOCKER_SSH_KNOWN_HOSTS", "DOCKER_SSH_HOST_KEY_SHA256", "DOCKER_SSH_COMMAND", "SSH_AUTH_SOCK",
        }
        tls_coordinates = {"DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_BUILDER_CA_SHA256"}
        if endpoint.startswith("ssh://"):
            if "SSH_AUTH_SOCK" in os.environ:
                child["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
            if any(name not in os.environ for name in ssh_coordinates - {"SSH_AUTH_SOCK"}):
                raise PipelineError("reviewed SSH builder transport is missing a host-key coordinate")
            if any(name in os.environ for name in tls_coordinates):
                raise PipelineError("TLS coordinates are not accepted for the reviewed SSH builder transport")
        elif endpoint.startswith("tcp://"):
            if any(name not in os.environ for name in tls_coordinates):
                raise PipelineError("reviewed TCP builder transport is missing a TLS coordinate")
            if any(name in os.environ for name in ssh_coordinates):
                raise PipelineError("SSH coordinates are not accepted for the reviewed TCP builder transport")
        else:
            if any(name in os.environ for name in ssh_coordinates | tls_coordinates):
                raise PipelineError("ambient SSH/TLS coordinates are not accepted for this builder transport")
    _CLOUDSDK_CONFIG = None
    if stage in {"preflight", "push"}:
        cloud_config_value = os.environ.get("CLOUDSDK_CONFIG", "")
        if not cloud_config_value:
            raise PipelineError(
                "cloud stages require an explicit private CLOUDSDK_CONFIG directory"
            )
        _CLOUDSDK_CONFIG = str(reviewed_cloud_config_directory(cloud_config_value))
    _CHILD_ENVIRONMENT = child


def cloud_child_environment() -> dict[str, str]:
    """Return the cloud-only environment for one explicitly reviewed gcloud call."""
    if _CLOUDSDK_CONFIG is None:
        raise PipelineError("cloud child environment was not configured for this stage")
    return {"CLOUDSDK_CONFIG": _CLOUDSDK_CONFIG}


def revalidate_native_builder_snapshot(
    expected_snapshot: dict[str, object],
) -> dict[str, object]:
    """Reprobe the selected worker and bind its post-build identity to receipt input."""
    current_snapshot = native_builder_snapshot()
    if current_snapshot is None:
        raise PipelineError("reviewed native Buildx worker changed or became unavailable after build")
    if builder_identity_binding(current_snapshot) != builder_identity_binding(expected_snapshot):
        raise PipelineError("reviewed native Buildx worker identity changed after build")
    return current_snapshot


def run(
    command: list[str],
    *,
    capture: bool = False,
    environment: dict[str, str] | None = None,
    pass_fds: tuple[int, ...] = (),
) -> subprocess.CompletedProcess[str]:
    """Run a fixed argv command without a shell or inherited configuration output."""
    if _CHILD_ENVIRONMENT is None:
        raise PipelineError("reviewed child environment has not been configured")
    if pass_fds:
        if command[:2] != ["skopeo", "copy"] or len(pass_fds) != 1 or any(
            not isinstance(fd, int) or fd < 0 for fd in pass_fds
        ):
            raise PipelineError("descriptor inheritance is restricted to one Skopeo copy")
    child_environment = _CHILD_ENVIRONMENT
    if environment is not None:
        child_environment = dict(_CHILD_ENVIRONMENT)
        child_environment.update(environment)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=child_environment,
        text=True,
        capture_output=capture,
        check=False,
        pass_fds=pass_fds,
    )
    if completed.returncode:
        if capture and completed.stderr:
            raise PipelineError(completed.stderr.strip())
        raise PipelineError("command failed: " + " ".join(command[:3]))
    return completed


def _parse_operator_config(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PipelineError("operator configuration must be UTF-8 text") from error
    lines = text.splitlines()
    result: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise PipelineError(f"invalid operator configuration line {line_number}")
        name, value = line.split("=", 1)
        if not CONFIG_NAME.fullmatch(name) or name in result:
            raise PipelineError(f"invalid operator configuration name at line {line_number}")
        if name not in OPERATOR_CONFIG_KEYS:
            raise PipelineError(f"unknown operator configuration name at line {line_number}")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise PipelineError(f"control character in operator configuration at line {line_number}")
        result[name] = value
    return result


def read_operator_config_snapshot(path: Path) -> OperatorConfigSnapshot:
    """Read and hash one stable regular config fd without evaluating shell."""
    try:
        link_metadata = path.lstat()
    except FileNotFoundError as error:
        raise PipelineError("operator configuration file does not exist") from error
    except OSError as error:
        raise PipelineError("could not safely inspect operator configuration") from error
    if stat.S_ISLNK(link_metadata.st_mode):
        raise PipelineError("operator configuration must not be a symlink")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError as error:
        raise PipelineError("operator configuration file does not exist") from error
    except OSError as error:
        raise PipelineError("could not safely open operator configuration") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise PipelineError("operator configuration must be a regular, non-symlink file")
        if (metadata.st_dev, metadata.st_ino) != (link_metadata.st_dev, link_metadata.st_ino):
            raise PipelineError("operator configuration changed while it was opened")
        if metadata.st_uid != os.geteuid():
            raise PipelineError("operator configuration must be owned by the current user")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise PipelineError("operator configuration must have mode 0600")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            descriptor_metadata = os.fstat(handle.fileno())
            data = handle.read()
            final_metadata = os.fstat(handle.fileno())
            if (
                descriptor_metadata.st_size != final_metadata.st_size
                or descriptor_metadata.st_mtime_ns != final_metadata.st_mtime_ns
                or len(data) != final_metadata.st_size
            ):
                raise PipelineError("operator configuration changed while it was read")
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    return OperatorConfigSnapshot(
        values=_parse_operator_config(data),
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
    )


def read_operator_config(path: Path) -> dict[str, str]:
    """Compatibility wrapper returning values from one stable config read."""
    return dict(read_operator_config_snapshot(path).values)


def configured_environment_snapshot(
    config_path: Path, profile: str, source_ref: str
) -> tuple[dict[str, str], str, OperatorConfigSnapshot]:
    try:
        metadata = config_path.lstat()
    except FileNotFoundError as error:
        raise PipelineError("operator configuration file does not exist") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise PipelineError("operator configuration must not be a symlink")
    config_path = config_path.resolve(strict=True)
    try:
        config_path.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise PipelineError("operator configuration must live outside the repository")

    snapshot = read_operator_config_snapshot(config_path)
    operator_config = snapshot.values
    impersonated_account = operator_config.get("LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT", "")
    if not re.fullmatch(SERVICE_ACCOUNT_PATTERN, impersonated_account):
        raise PipelineError("LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT must be a service account email")

    configuration = selected_configuration(
        profile,
        operator_config,
        source_ref=source_ref,
        probe_config_path=ROOT / "config/archive-witness-probe.json",
        shadow_runtime_config_path=ROOT / "config/archive-v3-shadow-runtime.json",
    )
    # Build/push identity must be separate from the identity embedded in the
    # image, which is only the enclave control-plane token subject.
    if impersonated_account == configuration["ENCLAVE_RUN_SA_EMAIL"]:
        raise PipelineError("local builder identity must not be the enclave runtime identity")
    return configuration, impersonated_account, snapshot


def configured_environment(
    config_path: Path, profile: str, source_ref: str
) -> tuple[dict[str, str], str]:
    """Compatibility wrapper for callers that do not need the snapshot."""
    configuration, account, _ = configured_environment_snapshot(config_path, profile, source_ref)
    return configuration, account


def parse_exact_version(output: str, tool: str, expected: str) -> None:
    if expected not in output:
        raise PipelineError(f"{tool} version must include {expected}")


def preflight_tools(*, need_cloud: bool, allow_emulated_fallback: bool = False) -> None:
    parse_exact_version(run(["docker", "buildx", "version"], capture=True).stdout, "docker buildx", "buildx")
    expected_builder_name = os.environ.get("KIOKU_NATIVE_BUILDER_NAME", "")
    if expected_builder_name:
        if not BUILDER_NAME.fullmatch(expected_builder_name):
            raise PipelineError("KIOKU_NATIVE_BUILDER_NAME is not a safe reviewed builder name")
        nodes = selected_buildx_nodes(expected_builder_name)
    else:
        builders = buildx_ls_entries()
        current = [builder for builder in builders if buildx_builder_field(builder, "Current") is True]
        if len(current) != 1:
            raise PipelineError("Buildx ls did not identify exactly one current builder")
        nodes = buildx_builder_field(current[0], "Nodes")
        if not isinstance(nodes, list) or any(not isinstance(node, dict) for node in nodes):
            raise PipelineError("current Buildx builder has an invalid node list")
        if len(nodes) != 1:
            raise PipelineError("current Buildx builder must have exactly one node")
    platforms = set().union(*(buildx_node_platforms(node) for node in nodes)) if nodes else set()
    if "linux/amd64" not in platforms:
        raise PipelineError("Docker Buildx must advertise the exact linux/amd64 platform")
    parse_exact_version(run(["syft", "--version"], capture=True).stdout, "syft", SYFT_VERSION)
    parse_exact_version(run(["grype", "--version"], capture=True).stdout, "grype", GRYPE_VERSION)
    native = native_linux_builder()
    if not native and not allow_emulated_fallback:
        raise PipelineError("no reviewed, pinned native Linux/x86 builder is available; emulation requires explicit opt-in")
    parse_exact_version(run(["skopeo", "--version"], capture=True).stdout, "skopeo", "skopeo")
    if native:
        check_builder_disk_space(expected_builder_name)
    if need_cloud:
        parse_exact_version(
            run(["gcloud", "version"], capture=True, environment=cloud_child_environment()).stdout,
            "gcloud",
            GCLOUD_VERSION,
        )


def cargo_audit_executable() -> str:
    """Resolve cargo-audit from PATH or Cargo's standard install directory."""
    installed = shutil.which("cargo-audit")
    if installed is not None:
        return installed

    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo")).expanduser()
    candidate = cargo_home / "bin" / "cargo-audit"
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise PipelineError(
            f"cargo-audit {CARGO_AUDIT_VERSION} is required; install it with cargo install"
        ) from error
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or not os.access(candidate, os.X_OK)
    ):
        raise PipelineError("Cargo-installed cargo-audit must be a current-user-owned executable")
    return str(candidate)


def source_commit(source_ref: str) -> tuple[str, int]:
    if run(["git", "status", "--porcelain"], capture=True).stdout:
        raise PipelineError("release/image builds require a clean source tree, including no untracked files")
    commit = run(["git", "rev-parse", "HEAD"], capture=True).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PipelineError("could not determine the source commit")
    timestamp = run(["git", "log", "-1", "--format=%ct", commit], capture=True).stdout.strip()
    if not timestamp.isdecimal():
        raise PipelineError("could not determine the source commit timestamp")
    tag = release_tag(source_ref)
    if tag is not None:
        tag_commit = run(
            ["git", "rev-list", "-n", "1", f"refs/tags/{tag}"], capture=True
        ).stdout.strip()
        if tag_commit != commit:
            raise PipelineError("release tag must exist locally and resolve exactly to HEAD")
    return commit, int(timestamp)


def verify_source_unchanged(source_ref: str, expected_commit: str) -> None:
    commit, _ = source_commit(source_ref)
    if commit != expected_commit:
        raise PipelineError("source commit changed during the local image pipeline")


def immutable_source_archive_digest(commit: str) -> str:
    """Hash the exact deterministic tar stream used for the Docker context."""
    completed = subprocess.run(
        ["git", "archive", "--format=tar", commit],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise PipelineError("could not create the immutable source archive")
    return hashlib.sha256(completed.stdout).hexdigest()


@contextmanager
def source_snapshot(commit: str, *, expected_archive_digest: str | None = None):
    """Yield a Docker context materialized only from the attested Git commit."""
    with tempfile.TemporaryDirectory(prefix="kioku-source-") as temporary:
        directory = Path(temporary)
        archive = directory / "source.tar"
        context = directory / "context"
        context.mkdir(mode=0o700)
        run(["git", "archive", "--format=tar", f"--output={archive}", commit])
        archive_digest = sha256(archive)
        if expected_archive_digest is not None and archive_digest != expected_archive_digest:
            raise PipelineError("immutable source archive changed between attestation and build")
        try:
            with tarfile.open(archive, mode="r:") as source:
                source.extractall(context, filter="data")
        except (OSError, tarfile.TarError) as error:
            raise PipelineError("could not materialize the immutable source snapshot") from error
        # Keep the exact archive beside the extracted context for the whole
        # build. It is removed with the private temporary directory only after
        # BuildKit has consumed the immutable snapshot.
        yield context


def verify() -> None:
    """Run every former CI test/format/lint/audit gate in the former order."""
    contract_tests = (
        "test_local_image_pipeline.py",
        "test_agent_verify.py",
        "test_rust_build_lifecycle.py",
        "test_bootstrap_local_operator_config.py",
        "test_archive_witness_probe_config.py",
        "test_archive_v3_shadow_runtime_config.py",
        "test_select_build_configuration.py",
        "test_local_build_evidence.py",
        "test_coordinator_advancement_receipt.py",
        "test_release.py",
        "test_generate_capacity_fixture.py",
        "test_run_archive_capacity_harness.py",
        "test_run_archive_capacity_gate.py",
        "test_verify_archive_v3_capacity_report.py",
    )
    for name in contract_tests:
        run([sys.executable, str(ROOT / "scripts" / name)])
    run([str(ROOT / "scripts/agent-verify.sh"), "full"])
    audit = cargo_audit_executable()
    audit_version = run([audit, "--version"], capture=True).stdout
    parse_exact_version(audit_version, "cargo-audit", CARGO_AUDIT_VERSION)
    run([audit, "audit", "--ignore", "RUSTSEC-2023-0071"])


def signed_verification_receipt_valid(
    receipt: Path | None,
    signature: Path | None,
    public_key: Path | None,
    public_key_sha256: str | None,
    *,
    source_ref: str,
    source_commit: str,
) -> bool:
    """Verify an external, signed exhaustive-verification receipt for resume."""
    if not receipt or not signature or not public_key or not public_key_sha256:
        return False
    if _CHILD_ENVIRONMENT is None:
        return False
    safe_environment = dict(_CHILD_ENVIRONMENT)
    try:
        regular_owned_file(receipt, "verification receipt", private=True)
        regular_owned_file(signature, "verification receipt signature", private=True)
        regular_owned_file(public_key, "verification receipt public key")
        if not re.fullmatch(r"[0-9a-f]{64}", public_key_sha256):
            return False
        raw = read_owned_bytes(receipt, "verification receipt", private=True)
        signature_bytes = read_owned_bytes(signature, "verification receipt signature", private=True)
        public_key_bytes = read_owned_bytes(public_key, "verification receipt public key")
        data = json.loads(raw.decode("utf-8"))
        expected = {
            "schema_version": 1,
            "source_ref": source_ref,
            "source_commit": source_commit,
            "dockerfile_sha256": sha256(ROOT / "Dockerfile"),
            "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
        }
        if not isinstance(data, dict) or data != expected:
            return False
        if raw != (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"):
            return False
        fingerprint = subprocess.run(
            ["openssl", "pkey", "-pubin", "-pubout", "-outform", "DER"],
            input=public_key_bytes, capture_output=True, check=False,
            env=safe_environment,
        )
        if fingerprint.returncode or hashlib.sha256(fingerprint.stdout).hexdigest() != public_key_sha256:
            return False
        with tempfile.TemporaryDirectory(prefix="kioku-verification-receipt-") as temporary:
            directory = Path(temporary)
            receipt_copy = directory / "receipt"
            signature_copy = directory / "signature"
            public_key_copy = directory / "public.pem"
            for path, value in (
                (receipt_copy, raw),
                (signature_copy, signature_bytes),
                (public_key_copy, public_key_bytes),
            ):
                path.write_bytes(value)
                path.chmod(0o600)
            verified = subprocess.run(
                [
                    "openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                    "-inkey", str(public_key_copy), "-sigfile", str(signature_copy), "-in", str(receipt_copy),
                ],
                capture_output=True,
                check=False,
                env=safe_environment,
            )
            return verified.returncode == 0
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, PipelineError):
        return False


def release_tag(source_ref: str) -> str | None:
    if source_ref.startswith("refs/tags/"):
        source_ref = source_ref.removeprefix("refs/tags/")
    if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?", source_ref):
        return source_ref
    return None


def image_coordinates(
    configuration: dict[str, str], profile: str, commit: str, source_ref: str
) -> tuple[str, str]:
    prefix = "eval-" if profile == "evaluation" else ""
    tag = f"{prefix}{release_tag(source_ref) or f'{commit[:7]}-{int(time.time())}'}"
    repository = (
        f"{configuration['REGION']}-docker.pkg.dev/{configuration['PROJECT_ID']}/"
        f"{configuration['AR_REPOSITORY']}/{configuration['IMAGE_NAME']}"
    )
    return repository, f"{repository}:{tag}"


def docker_build_arguments(
    configuration: dict[str, str],
    profile: str,
    source_date_epoch: int,
    *,
    config_sha256: str,
) -> list[str]:
    # Deployment values are passed through one ephemeral BuildKit secret. Only
    # source/profile metadata is allowed in argv, so Docker history cannot
    # disclose the selected configuration.
    if not re.fullmatch(r"[0-9a-f]{64}", config_sha256):
        raise PipelineError("image configuration hash must be a lowercase sha256")
    argument_names = (
        ("SOURCE_DATE_EPOCH", str(source_date_epoch)),
        ("CONFIG_SHA256", config_sha256),
    )
    result: list[str] = []
    for name, value in argument_names:
        result.extend(["--build-arg", f"{name}={value}"])
    return result


def runtime_config(configuration: dict[str, str], profile: str) -> dict[str, str]:
    """Map the typed selector result to the image's runtime environment names."""
    mapping = {
        "KIOKU_BUILD_PROFILE": profile,
        "KMS_PROJECT": "ENCLAVE_KMS_PROJECT",
        "KMS_LOCATION": "ENCLAVE_KMS_LOCATION",
        "KMS_KEY_RING": "ENCLAVE_KMS_KEY_RING",
        "KMS_KEY": "ENCLAVE_KMS_KEY",
        "GCS_BUCKET": "ENCLAVE_GCS_BUCKET",
        "GCS_MEDIA_BUCKET": "ENCLAVE_GCS_MEDIA_BUCKET",
        "GCS_LEGACY_MEDIA_BUCKET": "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET",
        "RUN_SA_EMAIL": "ENCLAVE_RUN_SA_EMAIL",
        "ENCLAVE_AUDIENCE": "ENCLAVE_AUDIENCE",
        "ATTEST_STS_AUDIENCE": "ENCLAVE_ATTEST_STS_AUDIENCE",
    }
    for name in (
        "GOOGLE_DESKTOP_CLIENT_ID", "GOOGLE_IOS_CLIENT_ID", "GOOGLE_WEB_CLIENT_ID",
        "APPLE_TEAM_ID", "APPLE_KEY_ID", "APPLE_IOS_CLIENT_ID", "APPLE_MACOS_CLIENT_ID",
        "APPLE_WEB_CLIENT_ID", "APNS_TEAM_ID", "APNS_PRODUCTION_KEY_ID",
        "APNS_SANDBOX_KEY_ID", "ALLOWED_EMAILS", "ADMIN_USER_IDS", "BASE_URL", "WEB_ORIGIN",
        "BILLING_SERVICE_URL", "BILLING_SERVICE_AUDIENCE", "BILLING_ENFORCEMENT_MODE",
        "REVIEWER_AUTH_API_KEY", "REVIEWER_AUTH_UID", "REVIEWER_AUTH_EMAIL", "VERTEX_PROJECT",
        "VERTEX_LOCATION", "VERTEX_MODEL", "ENCLAVE_ACME", "ENCLAVE_ACME_DIRECTORY",
        "ENCLAVE_ACME_CONTACT", "ARCHIVE_WITNESS_SHADOW_MODE", "ARCHIVE_WITNESS_PROJECT_ID",
        "ARCHIVE_WITNESS_PROJECT_NUMBER", "ARCHIVE_WITNESS_DATABASE_ID", "ARCHIVE_V3_SHADOW_RUNTIME_MODE",
        "ARCHIVE_V3_ARCHIVE_BUCKET", "ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER",
        "ARCHIVE_V3_REGISTRY_KMS_VERSION", "ARCHIVE_V3_WITNESS_PROJECT_ID",
        "ARCHIVE_V3_WITNESS_PROJECT_NUMBER", "ARCHIVE_V3_WITNESS_DATABASE_ID",
        "ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT",
    ):
        mapping[name] = name
    values: dict[str, str] = {}
    for name, source in mapping.items():
        if name == "KIOKU_BUILD_PROFILE":
            values[name] = profile
        elif source in configuration:
            values[name] = configuration[source]
        else:
            values[name] = configuration[name]
    return values


def write_runtime_config(path: Path, configuration: dict[str, str], profile: str) -> str:
    encoded = runtime_config_bytes(configuration, profile)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise PipelineError("could not create the ephemeral image configuration") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return hashlib.sha256(encoded).hexdigest()


def runtime_config_bytes(configuration: dict[str, str], profile: str) -> bytes:
    values = runtime_config(configuration, profile)
    encoded = bytearray()
    for name in sorted(values):
        value = values[name]
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise PipelineError("runtime configuration contains a control character")
        encoded.extend(f"{name}={value}\n".encode("utf-8"))
    return bytes(encoded)


def write_config_snapshot(path: Path, data: bytes) -> None:
    """Materialize the already-read config bytes without reopening the source."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise PipelineError("could not create the ephemeral configuration snapshot") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _validate_owned_descriptor(
    descriptor: int,
    label: str,
    *,
    mode: int | None = None,
    read_only: bool = False,
) -> os.stat_result:
    try:
        metadata = os.fstat(descriptor)
        descriptor_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
    except OSError as error:
        raise PipelineError(f"{label} cannot be inspected safely") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or (mode is not None and stat.S_IMODE(metadata.st_mode) != mode)
        or (read_only and descriptor_flags & os.O_ACCMODE != os.O_RDONLY)
    ):
        raise PipelineError(f"{label} must be one current-user-owned regular file")
    return metadata


def _open_owned(path: Path, label: str, *, private: bool = False, mode: int | None = None) -> int:
    """Open one stable current-user-owned regular file without following links."""
    try:
        link_metadata = path.lstat()
    except OSError as error:
        raise PipelineError(f"{label} is unavailable") from error
    if stat.S_ISLNK(link_metadata.st_mode):
        raise PipelineError(f"{label} must not be a symlink")
    canonical = canonical_path(path, label)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise PipelineError(f"{label} cannot be opened safely") from error
    try:
        metadata = _validate_owned_descriptor(
            descriptor,
            label,
            mode=0o600 if private else mode,
            read_only=True,
        )
        if (metadata.st_dev, metadata.st_ino) != (link_metadata.st_dev, link_metadata.st_ino):
            raise PipelineError(f"{label} must be one current-user-owned regular file")
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    return descriptor


def regular_owned_file(path: Path, label: str, *, private: bool = False) -> None:
    """Reject symlinks, replacement races, and files owned by another user."""
    descriptor = _open_owned(path, label, private=private)
    os.close(descriptor)


def owned_file_identity(path: Path, label: str, *, mode: int | None = None) -> tuple[int, int]:
    """Return an exact regular-file identity after owner/mode/link checks."""
    descriptor = _open_owned(path, label, mode=mode)
    try:
        metadata = os.fstat(descriptor)
        return metadata.st_dev, metadata.st_ino
    finally:
        os.close(descriptor)


def read_owned_bytes(path: Path, label: str, *, private: bool = False) -> bytes:
    """Read bytes from the same validated descriptor used for the checks."""
    descriptor = _open_owned(path, label, private=private)
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            descriptor_metadata = os.fstat(handle.fileno())
            data = handle.read()
            final_metadata = os.fstat(handle.fileno())
            if (
                descriptor_metadata.st_size != final_metadata.st_size
                or descriptor_metadata.st_mtime_ns != final_metadata.st_mtime_ns
                or len(data) != final_metadata.st_size
            ):
                raise PipelineError(f"{label} changed while it was read")
            return data
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_immutable_file(path: Path, data: bytes, label: str) -> None:
    """Write once, or accept only the exact same already-existing bytes."""
    if path.exists() or path.is_symlink():
        regular_owned_file(path, label, private=True)
        try:
            existing = read_owned_bytes(path, label, private=True)
        except OSError as error:
            raise PipelineError(f"cannot read existing {label}") from error
        if existing != data:
            raise PipelineError(f"refusing to overwrite existing {label}")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        # A concurrent writer is accepted only if it wrote these exact bytes.
        return write_immutable_file(path, data, label)
    except OSError as error:
        raise PipelineError(f"cannot write {label}") from error
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        descriptor = -1
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def write_evidence(path: Path, evidence: dict[str, object]) -> None:
    encoded = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if path.exists() or path.is_symlink():
        regular_owned_file(path, "build evidence", private=True)
        try:
            existing_raw = read_owned_bytes(path, "build evidence", private=True)
            existing = json.loads(existing_raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PipelineError("existing build evidence is not valid JSON") from error
        if not isinstance(existing, dict) or set(existing) != set(evidence):
            raise PipelineError("existing build evidence does not match this run")
        if existing_raw != (json.dumps(existing, sort_keys=True, indent=2) + "\n").encode("utf-8"):
            raise PipelineError("existing build evidence is not canonical JSON")
        if any(
            existing.get(field) != value
            for field, value in evidence.items()
            if field != "completed_at"
        ):
            raise PipelineError("existing build evidence does not match this run")
        return
    write_immutable_file(path, encoded, "build evidence")


def sha256(path: Path, *, mode: int | None = None) -> str:
    descriptor = _open_owned(path, "hash input", mode=mode)
    try:
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            descriptor_metadata = os.fstat(handle.fileno())
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
            final_metadata = os.fstat(handle.fileno())
            if descriptor_metadata.st_size != final_metadata.st_size or descriptor_metadata.st_mtime_ns != final_metadata.st_mtime_ns:
                raise PipelineError("hash input changed while it was hashed")
            return digest
    except OSError as error:
        raise PipelineError(f"cannot hash {path}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def source_repository() -> str:
    value = run(["git", "remote", "get-url", "origin"], capture=True).stdout.strip()
    if value.startswith("git@github.com:"):
        value = "https://github.com/" + value.removeprefix("git@github.com:")
    if value.endswith(".git"):
        value = value[:-4]
    if not re.fullmatch(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise PipelineError("origin must be a GitHub HTTPS or SSH repository URL")
    return value


def active_docker_host() -> str:
    """Return the endpoint for the same Docker context used by buildx."""
    host = run(
        [
            "docker",
            "context",
            "inspect",
            "--format",
            '{{ (index .Endpoints "docker").Host }}',
        ],
        capture=True,
    ).stdout.strip()
    if not re.fullmatch(r"(?:unix|tcp|ssh)://[^\s\x00-\x1f\x7f]+", host):
        raise PipelineError("active Docker context returned an invalid endpoint")
    return host


def sbom_and_scan(image_uri: str, output_dir: Path, *, artifact_ref: str | None = None) -> dict[str, str]:
    sbom_path = output_dir / "enclave-sbom.spdx.json"
    if sbom_path.exists() or sbom_path.is_symlink():
        regular_owned_file(sbom_path, "SBOM output", private=True)
    scan_target = artifact_ref or f"docker:{image_uri}"
    syft_environment = (
        {"DOCKER_HOST": active_docker_host()}
        if scan_target.startswith("docker:")
        else None
    )
    run(
        ["syft", scan_target, "-o", f"spdx-json={sbom_path}"],
        environment=syft_environment,
    )
    try:
        sbom = json.loads(read_owned_bytes(sbom_path, "SBOM output").decode("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineError("syft did not produce a valid SPDX JSON SBOM") from error
    package_names = {package.get("name", "").lower() for package in sbom.get("packages", [])}
    missing = sorted(REQUIRED_SBOM_PACKAGES - package_names)
    if missing:
        raise PipelineError("SBOM is missing auditable Rust packages: " + ", ".join(missing))
    harden_private_output(sbom_path, "SBOM output")
    # Capture only scan output, never selected configuration or credentials.
    scan = run(
        ["grype", f"sbom:{sbom_path}", "--only-fixed", "--fail-on", "high", "-o", "json"],
        capture=True,
    )
    scan_path = output_dir / "enclave-scan.json"
    write_immutable_file(scan_path, scan.stdout.encode("utf-8"), "scan output")
    return {
        "sbom_path": str(sbom_path),
        "scan_path": str(scan_path),
        "sbom_sha256": sha256(sbom_path),
        "scan_sha256": sha256(scan_path),
    }


def acquire_run_lock(output_dir: Path):
    """Hold one non-inheritable per-output run lock for the whole pipeline."""
    path = output_dir / ".run.lock"
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise PipelineError("could not create the output run lock") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise PipelineError("output run lock must be a current-user-owned mode-0600 file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise PipelineError("another local enclave pipeline run holds the output lock") from error
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def release_run_lock(descriptor: int | None) -> None:
    if descriptor is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def write_stage_receipt(output_dir: Path, stage: str, inputs: dict[str, object], outputs: dict[str, object]) -> Path:
    """Atomically write a redacted content-addressed receipt for resume."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", stage):
        raise PipelineError("stage receipt name is invalid")
    payload = {
        "schema_version": 1,
        "stage": stage,
        "inputs": inputs,
        "outputs": outputs,
    }
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    receipt_hash = hashlib.sha256(encoded).hexdigest()
    path = output_dir / f"{stage}-receipt-{receipt_hash}.json"
    write_immutable_file(path, encoded, f"{stage} receipt")
    return path


def validate_receipt_outputs(output_dir: Path, stage: str, payload: dict[str, object]) -> bool:
    outputs = payload.get("outputs")
    if not isinstance(outputs, dict):
        return False
    if stage == "build":
        artifact = outputs.get("artifact")
        artifact_sha256 = outputs.get("artifact_sha256")
        artifact_manifest_digest = outputs.get("artifact_manifest_digest")
        if (
            outputs.get("builder_mode") not in {"native-linux-amd64", "emulated-fallback"}
            or not isinstance(artifact, str)
            or not isinstance(artifact_sha256, str)
            or not isinstance(artifact_manifest_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)
            or not DIGEST.fullmatch(artifact_manifest_digest)
        ):
            return False
        post_builder = outputs.get("builder_post")
        receipt_inputs = payload.get("inputs")
        if not isinstance(post_builder, dict) or not isinstance(receipt_inputs, dict):
            return False
        if outputs["builder_mode"] == "native-linux-amd64":
            pre_builder = receipt_inputs.get("builder")
            if not isinstance(pre_builder, dict):
                return False
            try:
                if builder_identity_binding(post_builder) != builder_identity_binding(pre_builder):
                    return False
            except PipelineError:
                return False
        elif post_builder != {"mode": "emulated-fallback"}:
            return False
        path = Path(artifact)
        try:
            regular_owned_file(path, "OCI artifact", private=True)
            return (
                sha256(path) == artifact_sha256
                and oci_archive_manifest_digest(path) == artifact_manifest_digest
            )
        except PipelineError:
            return False
    if stage == "scan":
        inputs = payload.get("inputs")
        if not isinstance(inputs, dict):
            return False
        if (
            outputs.get("artifact_sha256") != inputs.get("artifact_sha256")
            or outputs.get("artifact_manifest_digest") != inputs.get("artifact_manifest_digest")
        ):
            return False
        for name, digest_name in (("sbom_path", "sbom_sha256"), ("scan_path", "scan_sha256")):
            path_value = outputs.get(name)
            digest_value = outputs.get(digest_name)
            if not isinstance(path_value, str) or not isinstance(digest_value, str):
                return False
            path = Path(path_value)
            try:
                regular_owned_file(path, f"{name} output", private=True)
                if sha256(path) != digest_value:
                    return False
            except PipelineError:
                return False
        return True
    if stage == "push":
        return isinstance(outputs.get("image_digest"), str) and bool(
            DIGEST.fullmatch(str(outputs["image_digest"]))
        )
    if stage == "evidence":
        for name, digest_name in (
            ("manifest", "manifest_sha256"),
            ("metadata", "metadata_sha256"),
        ):
            path_value = outputs.get(name)
            digest_value = outputs.get(digest_name)
            if path_value is None and name == "metadata":
                continue
            if not isinstance(path_value, str) or not isinstance(digest_value, str):
                return False
            path = Path(path_value)
            try:
                regular_owned_file(path, f"{name} output", private=True)
                if sha256(path) != digest_value:
                    return False
            except PipelineError:
                return False
        return True
    return True


def stage_receipt_candidates(
    output_dir: Path,
    stage: str,
    inputs: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    """Return strictly validated receipt payloads for one stage.

    Receipt filenames are content addresses, and every payload is canonical,
    schema-bound, path-safe, and output-validated.  A caller may additionally
    bind the receipt to exact expected inputs.  More than one valid receipt is
    corruption/ambiguity, never a reason to choose lexicographically.
    """
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", stage):
        return []
    receipt_pattern = re.compile(rf"{re.escape(stage)}-receipt-([0-9a-f]{{64}})\.json\Z")
    candidates: list[dict[str, object]] = []
    for path in sorted(output_dir.glob(f"{stage}-receipt-*.json")):
        match = receipt_pattern.fullmatch(path.name)
        if match is None:
            continue
        try:
            regular_owned_file(path, f"{stage} receipt", private=True)
            encoded = read_owned_bytes(path, f"{stage} receipt", private=True)
            if hashlib.sha256(encoded).hexdigest() != match.group(1):
                continue
            payload = json.loads(encoded.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, PipelineError):
            continue
        if not (
            isinstance(payload, dict)
            and payload.get("schema_version") == 1
            and payload.get("stage") == stage
            and encoded == (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
            and (inputs is None or payload.get("inputs") == inputs)
            and validate_receipt_outputs(output_dir, stage, payload)
        ):
            continue
        candidates.append(payload)
    if len(candidates) > 1:
        raise PipelineError(f"multiple valid {stage} receipts are ambiguous")
    return candidates


def valid_stage_receipt(output_dir: Path, stage: str, inputs: dict[str, object]) -> dict[str, object] | None:
    candidates = stage_receipt_candidates(output_dir, stage, inputs)
    return candidates[0] if candidates else None


def scan_database_identity() -> dict[str, object]:
    """Require a bounded, fresh Grype advisory database before promotion."""
    status = run(["grype", "db", "status", "-o", "json"], capture=True).stdout
    try:
        parsed = json.loads(status)
    except json.JSONDecodeError as error:
        raise PipelineError("Grype vulnerability database status is not JSON") from error
    if not isinstance(parsed, dict) or parsed.get("valid") is not True:
        raise PipelineError("Grype vulnerability database is not marked valid")
    built = parsed.get("built") or parsed.get("builtAt") or parsed.get("built_at")
    if not isinstance(built, str):
        raise PipelineError("Grype vulnerability database has no build timestamp")
    try:
        timestamp = datetime.fromisoformat(built.replace("Z", "+00:00"))
    except ValueError as error:
        raise PipelineError("Grype vulnerability database timestamp is invalid") from error
    age = (datetime.now(timezone.utc) - timestamp.astimezone(timezone.utc)).total_seconds()
    if age < 0 or age > SCAN_MAX_AGE_SECONDS:
        raise PipelineError("Grype vulnerability database is stale")
    identity = parsed.get("version") or parsed.get("schemaVersion")
    if identity is None:
        raise PipelineError("Grype vulnerability database identity is missing")
    checksum = parsed.get("checksum")
    if not isinstance(checksum, str) or not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", checksum):
        raise PipelineError("Grype vulnerability database checksum is missing or invalid")
    source = parsed.get("source") or parsed.get("url") or parsed.get("from")
    if not isinstance(source, str) or not re.fullmatch(r"https://grype\.anchore\.io/[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+", source):
        raise PipelineError("Grype vulnerability database source identity is missing or untrusted")
    return {"version": identity, "built": built, "valid": True, "checksum": checksum, "source": source}


def create_release_evidence(
    output_dir: Path,
    *,
    config_path: Path,
    configuration: dict[str, str],
    config_sha256: str,
    source_archive_sha256: str,
    source_ref: str,
    source_commit: str,
    image_uri: str,
    image_digest: str,
    created_at: str,
    expected_sbom_sha256: str,
    expected_scan_sha256: str,
) -> None:
    tag = release_tag(source_ref)
    if tag is None:
        return
    if not image_uri or not DIGEST.fullmatch(image_digest):
        raise PipelineError("release evidence requires an immutable image digest")
    repository = source_repository()
    owner_repository = repository.removeprefix("https://github.com/")
    metadata_path = output_dir / "enclave-release.json"
    voice_quality_gate = run(
        [sys.executable, str(ROOT / "scripts/check_voice_release_gate.py")], capture=True
    ).stdout.strip()
    metadata = {
        "schema_version": 9,
        "source_repository": repository,
        "source_ref": tag,
        "source_commit": source_commit,
        "image_uri": image_uri,
        "image_digest_uri": image_uri.rsplit(":", 1)[0] + "@" + image_digest,
        "image_digest": image_digest,
        "release_url": f"https://github.com/{owner_repository}/releases/tag/{tag}",
        "build_profile": "production",
        "voice_quality_gate": voice_quality_gate,
        "billing_enforcement_mode": configuration["BILLING_ENFORCEMENT_MODE"],
        "gcs_bucket": configuration["ENCLAVE_GCS_BUCKET"],
        "gcs_media_bucket": configuration["ENCLAVE_GCS_MEDIA_BUCKET"],
        "gcs_legacy_media_bucket": configuration["ENCLAVE_GCS_LEGACY_MEDIA_BUCKET"],
        "archive_witness_shadow_mode": configuration["ARCHIVE_WITNESS_SHADOW_MODE"],
        "archive_witness_project_id": configuration["ARCHIVE_WITNESS_PROJECT_ID"],
        "archive_witness_project_number": configuration["ARCHIVE_WITNESS_PROJECT_NUMBER"],
        "archive_witness_database_id": configuration["ARCHIVE_WITNESS_DATABASE_ID"],
        "archive_v3_shadow_runtime_mode": configuration["ARCHIVE_V3_SHADOW_RUNTIME_MODE"],
        "archive_v3_archive_bucket": configuration["ARCHIVE_V3_ARCHIVE_BUCKET"],
        "archive_v3_archive_gcs_project_number": configuration["ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER"],
        "archive_v3_registry_kms_version": configuration["ARCHIVE_V3_REGISTRY_KMS_VERSION"],
        "archive_v3_witness_project_id": configuration["ARCHIVE_V3_WITNESS_PROJECT_ID"],
        "archive_v3_witness_project_number": configuration["ARCHIVE_V3_WITNESS_PROJECT_NUMBER"],
        "archive_v3_witness_database_id": configuration["ARCHIVE_V3_WITNESS_DATABASE_ID"],
        "archive_v3_archive_binding_commitment": configuration["ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT"],
    }
    if metadata_path.exists():
        raise PipelineError("refusing to overwrite release metadata")
    write_immutable_file(
        metadata_path,
        (json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        "release metadata",
    )
    run(
        [
            sys.executable,
            str(ROOT / "scripts/verify_release_metadata.py"),
            str(metadata_path),
            "--repository", owner_repository,
            "--tag", tag,
            "--commit", source_commit,
            "--image-repository", image_uri.rsplit(":", 1)[0],
            "--expected-gcs-bucket", configuration["ENCLAVE_GCS_BUCKET"],
            "--expected-gcs-media-bucket", configuration["ENCLAVE_GCS_MEDIA_BUCKET"],
            "--expected-gcs-legacy-media-bucket", configuration["ENCLAVE_GCS_LEGACY_MEDIA_BUCKET"],
        ],
        capture=True,
    )
    completed_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    gcloud_version_lines = [
        line.strip()
        for line in run(
            ["gcloud", "version"],
            capture=True,
            environment=cloud_child_environment(),
        ).stdout.splitlines()
        if line.strip()
    ]
    if not gcloud_version_lines:
        raise PipelineError("gcloud version output is empty")
    versions = {
        "docker-buildx": run(["docker", "buildx", "version"], capture=True).stdout.strip(),
        "syft": run(["syft", "--version"], capture=True).stdout.strip(),
        "grype": run(["grype", "--version"], capture=True).stdout.strip(),
        "gcloud": gcloud_version_lines[0],
    }
    command = [
        sys.executable,
        str(ROOT / "scripts/local_build_evidence.py"),
        "create",
        "--output", str(output_dir / "enclave-local-build-evidence.json"),
        "--repository", repository,
        "--tag", tag,
        "--commit", source_commit,
        "--image-uri", image_uri,
        "--image-digest-uri", image_uri.rsplit(":", 1)[0] + "@" + image_digest,
        "--image-digest", image_digest,
        "--config", str(config_path),
        "--config-sha256", config_sha256,
        "--source-archive-sha256", source_archive_sha256,
        "--dockerfile", str(ROOT / "Dockerfile"),
        "--cargo-lock", str(ROOT / "Cargo.lock"),
        "--release-metadata", str(metadata_path),
        "--sbom", str(output_dir / "enclave-sbom.spdx.json"),
        "--scan", str(output_dir / "enclave-scan.json"),
        "--expected-sbom-sha256", expected_sbom_sha256,
        "--expected-scan-sha256", expected_scan_sha256,
        "--created-at", created_at,
        "--completed-at", completed_at,
    ]
    for name, version in versions.items():
        command.extend(["--tool-version", f"{name}={version}"])
    run(command)


def temporary_docker_login(registry: str, docker_config: Path, access_token: str) -> None:
    if _CHILD_ENVIRONMENT is None:
        raise PipelineError("reviewed child environment has not been configured")
    login = subprocess.run(
        [
            "docker", "--config", str(docker_config), "login", registry,
            "--username", "oauth2accesstoken", "--password-stdin",
        ],
        cwd=ROOT,
        input=access_token + "\n",
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        env=dict(_CHILD_ENVIRONMENT),
    )
    if login.returncode:
        raise PipelineError("temporary Docker login with the builder identity failed")
    auth_file = docker_config / "config.json"
    if auth_file != docker_config / "config.json":
        raise PipelineError("temporary Docker auth path is not the exact isolated config file")
    raw = read_owned_bytes(auth_file, "temporary Docker auth file", private=True)
    try:
        auth = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PipelineError("temporary Docker auth file is not valid JSON") from error
    if not isinstance(auth, dict) or not isinstance(auth.get("auths"), dict) or registry not in auth["auths"]:
        raise PipelineError("temporary Docker auth file has no exact registry auth map")


def sha256_descriptor(descriptor: int, label: str, *, mode: int | None = None) -> str:
    """Hash a held read-only descriptor while leaving it ready for consumers."""
    metadata = _validate_owned_descriptor(descriptor, label, mode=mode, read_only=True)
    duplicate = -1
    try:
        duplicate = os.dup(descriptor)
        os.lseek(duplicate, 0, os.SEEK_SET)
        with os.fdopen(duplicate, "rb") as handle:
            duplicate = -1
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        final_metadata = os.fstat(descriptor)
        if metadata.st_size != final_metadata.st_size or metadata.st_mtime_ns != final_metadata.st_mtime_ns:
            raise PipelineError(f"{label} changed while it was hashed")
        return digest
    except OSError as error:
        raise PipelineError(f"{label} could not be hashed") from error
    finally:
        if duplicate >= 0:
            os.close(duplicate)
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError as error:
            raise PipelineError(f"{label} could not be rewound safely") from error


def oci_archive_manifest_digest_fd(
    descriptor: int,
    *,
    mode: int | None = None,
) -> str:
    """Parse and validate an OCI archive from one held read-only descriptor."""
    _validate_owned_descriptor(descriptor, "OCI artifact", mode=mode, read_only=True)
    duplicate = -1
    try:
        duplicate = os.dup(descriptor)
        os.lseek(duplicate, 0, os.SEEK_SET)
        handle = os.fdopen(duplicate, "rb")
        duplicate = -1
        with handle, tarfile.open(fileobj=handle, mode="r:") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            if len(names) != len(set(names)) or any(
                member.issym() or member.islnk() or member.name.startswith("/")
                or ".." in Path(member.name).parts
                for member in members
            ):
                raise PipelineError("OCI archive contains duplicate or unsafe members")
            index_members = [member for member in members if member.name == "index.json"]
            if len(index_members) != 1:
                raise PipelineError("OCI archive must contain exactly one index.json")
            index_member = index_members[0]
            if not index_member.isfile():
                raise PipelineError("OCI archive index.json must be a regular member")
            index_file = archive.extractfile(index_member)
            if index_file is None:
                raise PipelineError("OCI archive index.json cannot be read")
            index_bytes = index_file.read()
            index = json.loads(index_bytes.decode("utf-8"))
            manifests = index.get("manifests") if isinstance(index, dict) else None
            if not isinstance(manifests, list) or len(manifests) != 1 or not isinstance(manifests[0], dict):
                raise PipelineError("OCI archive must contain exactly one image manifest")
            digest = manifests[0].get("digest")
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise PipelineError("OCI archive manifest digest is invalid")
            manifest_size = manifests[0].get("size")
            if not isinstance(manifest_size, int) or manifest_size < 0:
                raise PipelineError("OCI archive manifest size is invalid")
            algorithm, encoded = digest.split(":", 1)
            member = archive.getmember(f"blobs/{algorithm}/{encoded}")
            if not member.isfile():
                raise PipelineError("OCI archive manifest blob is not a regular member")
            manifest_file = archive.extractfile(member)
            if manifest_file is None:
                raise PipelineError("OCI archive manifest cannot be read")
            manifest_bytes = manifest_file.read()
    except (OSError, tarfile.TarError, KeyError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PipelineError("OCI archive is not a valid regular archive") from error
    finally:
        if duplicate >= 0:
            os.close(duplicate)
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
        except OSError as error:
            raise PipelineError("OCI archive descriptor could not be rewound safely") from error
    if hashlib.sha256(manifest_bytes).hexdigest() != encoded:
        raise PipelineError("OCI archive manifest blob digest does not match its index")
    if len(manifest_bytes) != manifest_size:
        raise PipelineError("OCI archive manifest size does not match its index")
    return digest


def oci_archive_manifest_digest(artifact: Path, *, mode: int | None = None) -> str:
    """Return and validate the exact manifest digest named by an OCI archive."""
    descriptor = _open_owned(
        artifact,
        "OCI artifact",
        private=mode is None,
        mode=mode,
    )
    try:
        return oci_archive_manifest_digest_fd(descriptor, mode=mode)
    finally:
        os.close(descriptor)


def _validate_expected_oci_binding(
    expected_artifact_sha256: str,
    expected_manifest_digest: str,
) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_artifact_sha256):
        raise PipelineError("expected OCI artifact hash is invalid")
    if not DIGEST.fullmatch(expected_manifest_digest):
        raise PipelineError("expected OCI manifest digest is invalid")


def verify_oci_archive_fd(
    descriptor: int,
    expected_artifact_sha256: str,
    expected_manifest_digest: str,
    *,
    mode: int | None = None,
) -> None:
    """Rehash and parse one held OCI descriptor without reopening a pathname."""
    _validate_expected_oci_binding(expected_artifact_sha256, expected_manifest_digest)
    observed_artifact_sha256 = sha256_descriptor(descriptor, "OCI artifact", mode=mode)
    observed_manifest_digest = oci_archive_manifest_digest_fd(descriptor, mode=mode)
    if observed_artifact_sha256 != expected_artifact_sha256:
        raise PipelineError("OCI artifact no longer matches the scanned artifact hash")
    if observed_manifest_digest != expected_manifest_digest:
        raise PipelineError("OCI artifact no longer matches the scanned manifest digest")


def verify_oci_archive_binding(
    artifact: Path,
    expected_artifact_sha256: str,
    expected_manifest_digest: str,
    *,
    mode: int | None = None,
) -> None:
    """Rehash one stable OCI path and require the scanned receipt binding."""
    descriptor = _open_owned(
        artifact,
        "OCI artifact",
        private=mode is None,
        mode=mode,
    )
    try:
        verify_oci_archive_fd(
            descriptor,
            expected_artifact_sha256,
            expected_manifest_digest,
            mode=mode,
        )
    finally:
        os.close(descriptor)


def verify_quarantined_oci_archive(
    descriptor: int,
    expected_identity: tuple[int, int],
    expected_artifact_sha256: str,
    expected_manifest_digest: str,
) -> None:
    """Require the sealed quarantine inode/mode and both exact content hashes."""
    metadata = _validate_owned_descriptor(
        descriptor,
        "quarantined OCI artifact",
        mode=0o400,
        read_only=True,
    )
    actual_identity = metadata.st_dev, metadata.st_ino
    if actual_identity != expected_identity:
        raise PipelineError("quarantined OCI artifact inode changed")
    verify_oci_archive_fd(
        descriptor,
        expected_artifact_sha256,
        expected_manifest_digest,
        mode=0o400,
    )


@contextmanager
def quarantine_scanned_oci_archive(
    artifact: Path,
    expected_artifact_sha256: str,
    expected_manifest_digest: str,
):
    """Copy the scanned bytes through one stable descriptor before auth.

    The source pathname may be replaced after the scan.  The copy is made from
    an already validated descriptor, rehashed against both receipt bindings,
    and sealed as an unlinked mode-0400 descriptor in a private, non-writable
    directory. The descriptor is retained for Skopeo; no quarantine pathname
    remains after sealing.
    """
    quarantine = tempfile.TemporaryDirectory(prefix="kioku-scanned-oci-")
    quarantine_dir = Path(quarantine.name)
    quarantined = quarantine_dir / OCI_ARTIFACT_NAME
    source_descriptor = -1
    writable_descriptor = -1
    sealed_descriptor = -1
    try:
        source_descriptor = _open_owned(artifact, "scanned OCI artifact", private=True)
        source_handle = os.fdopen(source_descriptor, "rb")
        source_descriptor = -1
        try:
            # Bind the stable source descriptor before copying it into the
            # unlinked quarantine; the later copy verification covers any
            # in-place source mutation during the transfer.
            verify_oci_archive_fd(
                source_handle.fileno(),
                expected_artifact_sha256,
                expected_manifest_digest,
                mode=0o600,
            )
            source_metadata = os.fstat(source_handle.fileno())
            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            writable_descriptor = os.open(quarantined, flags, 0o600)
            with os.fdopen(writable_descriptor, "wb") as target_handle:
                writable_descriptor = -1
                shutil.copyfileobj(source_handle, target_handle, length=1024 * 1024)
                target_handle.flush()
                os.fsync(target_handle.fileno())
            final_source_metadata = os.fstat(source_handle.fileno())
            if (
                source_metadata.st_size != final_source_metadata.st_size
                or source_metadata.st_mtime_ns != final_source_metadata.st_mtime_ns
            ):
                raise PipelineError("scanned OCI artifact changed while it was quarantined")
        finally:
            source_handle.close()
        # Close the writable copy first, then reopen the exact O_NOFOLLOW file
        # as read-only and seal its mode through that descriptor.
        sealed_descriptor = _open_owned(
            quarantined, "quarantined OCI artifact", private=True
        )
        os.fchmod(sealed_descriptor, 0o400)
        sealed_metadata = _validate_owned_descriptor(
            sealed_descriptor,
            "quarantined OCI artifact",
            mode=0o400,
            read_only=True,
        )
        quarantine_identity = sealed_metadata.st_dev, sealed_metadata.st_ino
        verify_quarantined_oci_archive(
            sealed_descriptor,
            quarantine_identity,
            expected_artifact_sha256,
            expected_manifest_digest,
        )
        try:
            os.unlink(quarantined)
            parent_descriptor = os.open(
                quarantine_dir,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
            quarantine_dir.chmod(0o500)
            parent_descriptor = os.open(
                quarantine_dir,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except OSError as error:
            raise PipelineError("could not seal the unlinked OCI quarantine") from error
        yield sealed_descriptor
    finally:
        if writable_descriptor >= 0:
            os.close(writable_descriptor)
        if sealed_descriptor >= 0:
            os.close(sealed_descriptor)
        if source_descriptor >= 0:
            os.close(source_descriptor)
        try:
            quarantine_dir.chmod(0o700)
        except OSError:
            pass
        quarantine.cleanup()


def authenticate_and_push(
    image_uri: str,
    configuration: dict[str, str],
    impersonated_account: str,
    *,
    artifact: Path,
    expected_artifact_sha256: str,
    expected_manifest_digest: str,
) -> str:
    gcloud_prefix = ["gcloud", f"--impersonate-service-account={impersonated_account}"]
    registry = f"{configuration['REGION']}-docker.pkg.dev"
    with quarantine_scanned_oci_archive(
        artifact, expected_artifact_sha256, expected_manifest_digest
    ) as quarantined_descriptor:
        quarantine_metadata = _validate_owned_descriptor(
            quarantined_descriptor,
            "quarantined OCI artifact",
            mode=0o400,
            read_only=True,
        )
        quarantine_identity = quarantine_metadata.st_dev, quarantine_metadata.st_ino
        # This check is intentionally before the first credential acquisition.
        verify_quarantined_oci_archive(
            quarantined_descriptor,
            quarantine_identity,
            expected_artifact_sha256,
            expected_manifest_digest,
        )
        access_token = run(
            gcloud_prefix + ["auth", "print-access-token"],
            capture=True,
            environment=cloud_child_environment(),
        ).stdout.strip()
        if (
            len(access_token) < 20
            or len(access_token) > 8192
            or any(ord(character) < 33 or ord(character) == 127 for character in access_token)
        ):
            raise PipelineError("builder identity returned an invalid access token")
        with tempfile.TemporaryDirectory(prefix="kioku-docker-auth-") as temporary:
            docker_config = Path(temporary)
            docker_config.chmod(0o700)
            temporary_docker_login(registry, docker_config, access_token)
            auth_file = docker_config / "config.json"
            access_token = ""
            # Recheck immediately before Skopeo through the sealed descriptor.
            verify_quarantined_oci_archive(
                quarantined_descriptor,
                quarantine_identity,
                expected_artifact_sha256,
                expected_manifest_digest,
            )
            digest_file = docker_config / "pushed.digest"
            run(
                ["skopeo", "copy", "--authfile", str(auth_file), "--digestfile", str(digest_file),
                 "--preserve-digests",
                 f"oci-archive:/dev/fd/{quarantined_descriptor}", f"docker://{image_uri}"],
                capture=True,
                pass_fds=(quarantined_descriptor,),
            )
            # Rehash through the still-held descriptor after Skopeo returns.
            # No pathname or writable descriptor exists for the quarantine.
            verify_quarantined_oci_archive(
                quarantined_descriptor,
                quarantine_identity,
                expected_artifact_sha256,
                expected_manifest_digest,
            )
            regular_owned_file(digest_file, "skopeo digest file")
            digest = read_owned_bytes(digest_file, "skopeo digest file").decode("ascii").strip()
            if not DIGEST.fullmatch(digest) or digest != expected_manifest_digest:
                raise PipelineError("skopeo digest does not preserve the exact local OCI manifest")
            if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
                raise PipelineError("push did not produce an immutable image digest")
    registry_digest = run(
        gcloud_prefix
        + [
            "artifacts",
            "docker",
            "images",
            "describe",
            image_uri,
            "--format=value(image_summary.digest)",
        ],
        capture=True,
        environment=cloud_child_environment(),
    ).stdout.strip()
    if not DIGEST.fullmatch(registry_digest) or registry_digest != digest:
        raise PipelineError("registry digest mismatch for the pushed image")
    if registry_digest != expected_manifest_digest:
        raise PipelineError("registry digest mismatch for the pushed image")
    return digest


def verify_registry_digest(
    image_uri: str,
    impersonated_account: str,
    expected_digest: str,
) -> None:
    if not DIGEST.fullmatch(expected_digest):
        raise PipelineError("push receipt contains an invalid image digest")
    registry_digest = run(
        [
            "gcloud",
            f"--impersonate-service-account={impersonated_account}",
            "artifacts",
            "docker",
            "images",
            "describe",
            image_uri,
            "--format=value(image_summary.digest)",
        ],
        capture=True,
        environment=cloud_child_environment(),
    ).stdout.strip()
    if registry_digest != expected_digest:
        raise PipelineError("existing push receipt does not match Artifact Registry")


def require_apply(stage: str, apply: bool) -> None:
    if stage != "preflight" and not apply:
        raise PipelineError(f"{stage} changes local or remote state; rerun with --apply")


def harden_private_output(path: Path, label: str) -> None:
    regular_owned_file(path, label)
    try:
        path.chmod(0o600)
    except OSError as error:
        raise PipelineError(f"could not set safe mode on {label}") from error
    regular_owned_file(path, label, private=True)


def main() -> None:
    # Buildx and other child tools create bookkeeping files in private release
    # directories. Keep those files private even when the operator's shell
    # has a permissive default umask.
    os.umask(0o077)
    parser = argparse.ArgumentParser(
        description="Run the local enclave CI/image pipeline without GitHub Actions."
    )
    parser.add_argument("stage", nargs="?", choices=("preflight", "verify", "build", "push"), default="preflight")
    parser.add_argument("--config", type=Path, required=True, help="external mode-0600 KEY=VALUE operator configuration")
    parser.add_argument("--profile", choices=("production", "evaluation"), default="production")
    parser.add_argument("--source-ref", default="HEAD")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--apply", action="store_true", help="acknowledge local/remote state changes")
    parser.add_argument("--resume", action="store_true", help="resume only from matching content-addressed stage receipts")
    parser.add_argument(
        "--allow-emulated-fallback",
        action="store_true",
        help="explicitly allow the non-native builder fallback (never implicit)",
    )
    parser.add_argument(
        "--confirm-emulated-release",
        action="store_true",
        help="separately confirm the explicitly opted-in fallback for a release tag",
    )
    parser.add_argument("--verification-receipt", type=Path)
    parser.add_argument("--verification-signature", type=Path)
    parser.add_argument("--verification-public-key", type=Path)
    parser.add_argument("--verification-public-key-sha256")
    arguments = parser.parse_args()

    run_lock_descriptor: int | None = None
    snapshot_directory: tempfile.TemporaryDirectory[str] | None = None
    try:
        if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
            raise PipelineError(
                "GOOGLE_APPLICATION_CREDENTIALS is not accepted by the local release pipeline; use reviewed gcloud identity configuration"
            )
        if (
            arguments.source_ref.startswith("v")
            or arguments.source_ref.startswith("refs/tags/v")
        ) and arguments.profile != "production":
            raise PipelineError("release tags may only build the production profile")
        configuration, impersonated_account, config_snapshot = configured_environment_snapshot(
            arguments.config, arguments.profile, arguments.source_ref
        )
        configure_direct_child_environment(arguments.stage)
        require_apply(arguments.stage, arguments.apply)
        preflight_tools(
            need_cloud=arguments.stage in ("preflight", "push"),
            allow_emulated_fallback=arguments.allow_emulated_fallback,
        )
        if arguments.stage == "preflight":
            print("local enclave pipeline preflight passed; no build, authentication, or push occurred")
            return
        if arguments.stage == "verify":
            verify()
            print("local enclave verification passed")
            return
        if arguments.output_dir is None:
            raise PipelineError("build and push require --output-dir for unsigned evidence")
        if arguments.output_dir.is_symlink():
            raise PipelineError("output directory must not be a symlink")
        output_dir = arguments.output_dir.resolve()
        if output_dir.is_symlink():
            raise PipelineError("output directory must not be a symlink")
        try:
            output_dir.relative_to(ROOT)
        except ValueError:
            pass
        else:
            raise PipelineError("output directory must live outside the source repository")
        if output_dir.exists() and not arguments.resume:
            raise PipelineError("output directory exists; pass --resume only for exact receipt reuse")
        try:
            output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            output_metadata = output_dir.stat()
        except OSError as error:
            raise PipelineError("output directory is unavailable") from error
        if not stat.S_ISDIR(output_metadata.st_mode) or output_metadata.st_uid != os.geteuid():
            raise PipelineError("output directory must be a current-user-owned directory")
        if stat.S_IMODE(output_metadata.st_mode) & 0o077:
            raise PipelineError("output directory must not be group/world accessible")
        run_lock_descriptor = acquire_run_lock(output_dir)
        commit, source_date_epoch = source_commit(arguments.source_ref)
        release = release_tag(arguments.source_ref) is not None
        builder_snapshot = native_builder_snapshot()
        native = builder_snapshot is not None
        if not native:
            if not arguments.allow_emulated_fallback:
                raise PipelineError("no reviewed native Linux/x86 builder; pass --allow-emulated-fallback for an explicit emergency fallback")
            if release and not arguments.confirm_emulated_release:
                raise PipelineError("emulated fallback is forbidden for release tags without --confirm-emulated-release")
        if not (
            arguments.resume
            and signed_verification_receipt_valid(
                arguments.verification_receipt,
                arguments.verification_signature,
                arguments.verification_public_key,
                arguments.verification_public_key_sha256,
                source_ref=arguments.source_ref,
                source_commit=commit,
            )
        ):
            verify()
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        repository, image_uri = image_coordinates(
            configuration, arguments.profile, commit, arguments.source_ref
        )
        image_config_sha256 = hashlib.sha256(runtime_config_bytes(configuration, arguments.profile)).hexdigest()
        build_inputs = {
            "source_commit": commit,
            "source_archive_sha256": immutable_source_archive_digest(commit),
            "source_date_epoch": source_date_epoch,
            "config_sha256": config_snapshot.sha256,
            "image_config_sha256": image_config_sha256,
            "dockerfile_sha256": sha256(ROOT / "Dockerfile"),
            "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
            "builder_mode": "native-linux-amd64" if native else "emulated-fallback",
            "builder": builder_snapshot or {"mode": "emulated-fallback"},
        }
        artifact = output_dir / OCI_ARTIFACT_NAME
        snapshot_directory = tempfile.TemporaryDirectory(prefix="kioku-config-snapshot-")
        snapshot_path = Path(snapshot_directory.name) / "operator.env"
        write_config_snapshot(snapshot_path, config_snapshot.data)
        build_receipt = valid_stage_receipt(output_dir, "build", build_inputs) if arguments.resume else None
        if build_receipt is None:
            if artifact.exists() or artifact.is_symlink():
                raise PipelineError("refusing to overwrite an existing OCI artifact without an exact build receipt")
            with tempfile.TemporaryDirectory(prefix="kioku-image-config-") as temporary:
                config_secret = Path(temporary) / "runtime.env"
                generated_config_sha256 = write_runtime_config(config_secret, configuration, arguments.profile)
                if generated_config_sha256 != image_config_sha256:
                    raise PipelineError("runtime configuration changed while preparing the image secret")
                with source_snapshot(commit, expected_archive_digest=build_inputs["source_archive_sha256"]) as snapshot:
                    build_command = [
                        "docker", "buildx", "build",
                    ]
                    if native:
                        build_command.extend(["--builder", str(builder_snapshot["name"])])
                    build_command.extend([
                        "--platform", "linux/amd64",
                        *docker_build_arguments(
                            configuration,
                            arguments.profile,
                            source_date_epoch,
                            config_sha256=image_config_sha256,
                        ),
                        "--secret", f"id=kioku-config,src={config_secret}",
                    ])
                    # Both modes retain an immutable OCI archive. The
                    # emulated path is explicitly labeled in evidence, but it
                    # is never converted into a mutable daemon tag.
                    build_command.extend(["--output", f"type=oci,dest={artifact}"])
                    build_command.append(str(snapshot))
                    run(build_command)
            post_builder_snapshot: dict[str, object] = {"mode": "emulated-fallback"}
            if native:
                # Reprobe the exact selected node after the build.  The
                # post-build identity must match the pre-build receipt input;
                # the disk probe alone is not sufficient if a named builder
                # was redirected to another worker during compilation.
                if not isinstance(builder_snapshot, dict):
                    raise PipelineError("native build is missing its pre-build worker snapshot")
                post_builder_snapshot = revalidate_native_builder_snapshot(builder_snapshot)
            harden_private_output(artifact, "OCI artifact")
            manifest_digest = oci_archive_manifest_digest(artifact)
            artifact_hash = sha256(artifact)
            build_receipt = {
                "outputs": {
                    "artifact": str(artifact),
                    "artifact_sha256": artifact_hash,
                    "artifact_manifest_digest": manifest_digest,
                    "builder_mode": "native-linux-amd64" if native else "emulated-fallback",
                    "builder_post": post_builder_snapshot,
                }
            }
            write_stage_receipt(
                output_dir,
                "build",
                build_inputs,
                build_receipt["outputs"],
            )
        build_outputs = build_receipt.get("outputs")
        if not isinstance(build_outputs, dict):
            raise PipelineError("build receipt outputs are invalid")
        if build_outputs.get("artifact") != str(artifact):
            raise PipelineError("build receipt artifact identity does not match this run")
        artifact_sha256 = build_outputs.get("artifact_sha256")
        artifact_manifest_digest = build_outputs.get("artifact_manifest_digest")
        if not isinstance(artifact_sha256, str) or not isinstance(artifact_manifest_digest, str):
            raise PipelineError("build receipt is missing artifact hashes")
        if (
            sha256(artifact) != artifact_sha256
            or oci_archive_manifest_digest(artifact) != artifact_manifest_digest
        ):
            raise PipelineError("OCI artifact changed after the build receipt")
        scan_db = scan_database_identity()
        scan_inputs = {
            **build_inputs,
            "artifact_sha256": artifact_sha256,
            "artifact_manifest_digest": artifact_manifest_digest,
            "scan_db": scan_db,
        }
        scan_receipt = valid_stage_receipt(output_dir, "scan", scan_inputs) if arguments.resume else None
        if scan_receipt is None:
            # Compatibility marker for the original stage contract:
            # sbom_and_scan(image_uri, output_dir)
            scan_outputs = sbom_and_scan(
                image_uri,
                output_dir,
                artifact_ref=f"oci-archive:{artifact}",
            )
            scan_outputs["artifact_sha256"] = artifact_sha256
            scan_outputs["artifact_manifest_digest"] = artifact_manifest_digest
            write_stage_receipt(output_dir, "scan", scan_inputs, scan_outputs)
            scan_receipt = {"outputs": scan_outputs}
        scan_outputs = scan_receipt.get("outputs") if isinstance(scan_receipt, dict) else None
        if not isinstance(scan_outputs, dict):
            raise PipelineError("scan receipt outputs are invalid")
        expected_sbom_sha256 = scan_outputs.get("sbom_sha256")
        expected_scan_sha256 = scan_outputs.get("scan_sha256")
        if (
            not isinstance(expected_sbom_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sbom_sha256)
            or not isinstance(expected_scan_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_scan_sha256)
        ):
            raise PipelineError("scan receipt is missing stable SBOM/scan hashes")
        if scan_outputs.get("sbom_path") != str(output_dir / "enclave-sbom.spdx.json"):
            raise PipelineError("scan receipt SBOM path is not the exact output")
        if scan_outputs.get("scan_path") != str(output_dir / "enclave-scan.json"):
            raise PipelineError("scan receipt scan path is not the exact output")
        # Build/scan can take long enough for an editor or another agent to
        # change this worktree. Refuse cloud auth and publication unless the
        # exact source/tag binding is still clean and unchanged.
        verify_source_unchanged(arguments.source_ref, commit)
        evidence: dict[str, object] = {
            "schema_version": 1,
            "build_profile": arguments.profile,
            "image_uri": image_uri,
            "image_repository": repository,
            "source_commit": commit,
            "source_date_epoch": source_date_epoch,
            "source_archive_sha256": build_inputs["source_archive_sha256"],
            "source_ref": arguments.source_ref,
            "sbom": "enclave-sbom.spdx.json",
            "scan": "enclave-scan.json",
            "config_sha256": config_snapshot.sha256,
            "image_config_sha256": image_config_sha256,
            "dockerfile_sha256": sha256(ROOT / "Dockerfile"),
            "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
            "created_at": created_at,
            "signed": False,
            "builder_mode": "native-linux-amd64" if native else "emulated-fallback",
            "fallback": not native,
            "builder": build_inputs["builder"],
            "source_archive": "immutable-git-archive",
        }
        if arguments.stage == "push":
            push_inputs = {
                "build_inputs": build_inputs,
                "image_uri": image_uri,
                "artifact_sha256": artifact_sha256,
                "artifact_manifest_digest": artifact_manifest_digest,
            }
            push_receipt = valid_stage_receipt(output_dir, "push", push_inputs) if arguments.resume else None
            if push_receipt is not None:
                push_outputs = push_receipt["outputs"]
                assert isinstance(push_outputs, dict)
                image_digest = str(push_outputs["image_digest"])
                verify_registry_digest(
                    image_uri, impersonated_account, image_digest
                )
            else:
                image_digest = authenticate_and_push(
                    image_uri, configuration, impersonated_account,
                    artifact=artifact,
                    expected_artifact_sha256=artifact_sha256,
                    expected_manifest_digest=artifact_manifest_digest,
                )
                write_stage_receipt(
                    output_dir,
                    "push",
                    push_inputs,
                    {"image_digest": image_digest},
                )
            evidence["image_digest"] = image_digest
            evidence_inputs = {
                **push_inputs,
                "image_digest": image_digest,
                "source_archive_sha256": build_inputs["source_archive_sha256"],
                "sbom_sha256": expected_sbom_sha256,
                "scan_sha256": expected_scan_sha256,
            }
            evidence_receipt = valid_stage_receipt(output_dir, "evidence", evidence_inputs) if arguments.resume else None
            if evidence_receipt is None:
                create_release_evidence(
                    output_dir,
                    config_path=snapshot_path,
                    configuration=configuration,
                    config_sha256=config_snapshot.sha256,
                    source_archive_sha256=str(build_inputs["source_archive_sha256"]),
                    source_ref=arguments.source_ref,
                    source_commit=commit,
                    image_uri=image_uri,
                    image_digest=image_digest,
                    created_at=created_at,
                    expected_sbom_sha256=expected_sbom_sha256,
                    expected_scan_sha256=expected_scan_sha256,
                )
                evidence_outputs: dict[str, object] = {}
                manifest_path = output_dir / "enclave-local-build-evidence.json"
                if manifest_path.exists():
                    evidence_outputs["manifest"] = str(manifest_path)
                    evidence_outputs["manifest_sha256"] = sha256(manifest_path)
                metadata_path = output_dir / "enclave-release.json"
                if metadata_path.exists():
                    evidence_outputs["metadata"] = str(metadata_path)
                    evidence_outputs["metadata_sha256"] = sha256(metadata_path)
                write_stage_receipt(output_dir, "evidence", evidence_inputs, evidence_outputs)
        evidence["completed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        write_evidence(output_dir / "build-evidence.json", evidence)
        print(f"unsigned build evidence written to {output_dir}")
    except PipelineError as error:
        print(f"local image pipeline: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    finally:
        release_run_lock(run_lock_descriptor)
        if snapshot_directory is not None:
            snapshot_directory.cleanup()


if __name__ == "__main__":
    main()
