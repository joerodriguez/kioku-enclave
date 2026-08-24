#!/usr/bin/env python3
"""Production ADR-0033 enclave release-train adapters.

The coordinator invokes this file from an exact detached enclave snapshot.  The
wrapper intentionally keeps the existing image pipeline and evidence tooling as
the stage executors, but gives them a strict coordinator boundary:

* prepare builds/scans an OCI artifact without cloud credentials;
* publish promotes that exact artifact, signs/verifies evidence, and publishes
  the immutable GitHub release; and
* verify checks the signed evidence bundle without remote mutation.

``state`` is a read-only provider used by the coordinator after publication. It
independently reads the immutable GitHub release/evidence and Artifact Registry
digest, then emits the coordinator live-state envelope.

All diagnostics go to stderr.  Successful stdout is one canonical JSON object.
The coordinator's reviewed environment allowlist supplies the paths and
non-secret coordinates documented in ``ENVIRONMENT`` below.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
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
import tempfile
import urllib.parse
from typing import Any, Iterator, Mapping, NamedTuple, Sequence

import local_image_pipeline as _image_pipeline
from local_image_pipeline import PipelineError, configured_environment_snapshot


ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "scripts" / "local_image_pipeline.py"
EVIDENCE = ROOT / "scripts" / "local_build_evidence.py"
BUNDLE_VERIFY = ROOT / "scripts" / "verify_local_evidence_bundle.py"

SCHEMA = "kioku.release.adapter-output.v1"
STATE_SCHEMA = "kioku.release.live-state.v1"
ZERO_DIGEST = "sha256:" + ("0" * 64)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[.-][0-9A-Za-z.-]+)?\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
IMAGE_REPOSITORY = re.compile(
    r"[a-z0-9-]+-docker\.pkg\.dev/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*\Z"
)
GITHUB_REPOSITORY = "joerodriguez/kioku-enclave"
_RELEASE_ASSET_NAMES = (
    "enclave-local-build-evidence.json",
    "enclave-local-build-evidence.sig",
    "enclave-release.json",
    "enclave-sbom.spdx.json",
    "enclave-scan.json",
)
SAFE_AMBIENT_GIT_ENV = frozenset({"GIT_NO_REPLACE_OBJECTS", "GIT_PAGER"})

# Names that must be added to the coordinator's explicit later-phase
# environment allowlist.  No credential is accepted by prepare.
ENVIRONMENT = {
    "coordinates": (
        "KIOKU_RELEASE_CONFIG_PATH",
        "KIOKU_RELEASE_EVIDENCE_PUBLIC_KEY",
        "KIOKU_RELEASE_EVIDENCE_PUBLIC_KEY_SHA256",
        "KIOKU_RELEASE_TAG_SIGNER_FINGERPRINT",
        "KIOKU_NATIVE_BUILDER_NAME",
        "KIOKU_NATIVE_BUILDER_ID",
        "DOCKER_HOST",
        "DOCKER_SSH_KNOWN_HOSTS",
        "DOCKER_SSH_HOST_KEY_SHA256",
        "DOCKER_SSH_COMMAND",
        "DOCKER_TLS_VERIFY",
        "DOCKER_CERT_PATH",
        "DOCKER_BUILDER_CA_SHA256",
        "SSH_AUTH_SOCK",
        "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG",
        "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG",
        "CLOUDSDK_CONFIG",
    ),
    "later_credentials": (
        "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY",
        "KIOKU_RELEASE_GITHUB_TOKEN",
        "KIOKU_RELEASE_GCP_READONLY_SERVICE_ACCOUNT",
    ),
}

NATIVE_BUILDER_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
NATIVE_BUILDER_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
TRANSPORT_ENDPOINT = re.compile(r"(?:unix|tcp|ssh)://[^\s\x00-\x1f\x7f]+\Z")
SSH_HOST_KEY = re.compile(r"SHA256:[A-Za-z0-9+/]+={0,2}\Z")
HEX_HASH = re.compile(r"[0-9a-f]{64}\Z")
CONFIG_SECRET_KEYS = frozenset({
    "auth",
    "auths",
    "clientsecret",
    "credhelpers",
    "credsstore",
    "identitytoken",
    "password",
    "registrytoken",
    "secret",
    "token",
    "username",
})


class AdapterError(RuntimeError):
    """A fail-closed adapter error whose detail is safe for stderr."""


class VerifiedTag(NamedTuple):
    """One signed annotated-tag object captured before untrusted work."""

    name: str
    object_id: str
    commit: str


def fail(message: str) -> "NoReturn":
    raise AdapterError(message)


def _canonical_path(path: Path, label: str) -> Path:
    """Resolve one path while allowing macOS's canonical /var alias only."""
    try:
        canonical = path.resolve(strict=True)
    except OSError:
        fail(f"{label} has an unsafe path")
    if canonical != path and not (
        path.parts[:2] == ("/", "var")
        and canonical.parts[:3] == ("/", "private", "var")
        and canonical.parts[3:] == path.parts[2:]
    ):
        fail(f"{label} has symlinked ancestry")
    return canonical


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def emit(value: Mapping[str, Any]) -> None:
    # Exactly one JSON document and no human-readable stdout.
    sys.stdout.write(canonical(dict(value)).decode("ascii"))


def _regular(path: Path, *, mode: int | None = None, private: bool = False) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"missing {path.name}")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        fail(f"{path.name} must be a regular file")
    if metadata.st_uid != os.geteuid():
        fail(f"{path.name} has an unexpected owner")
    expected = 0o600 if private else mode
    if expected is not None and stat.S_IMODE(metadata.st_mode) != expected:
        fail(f"{path.name} has unsafe permissions")


def _private_directory(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_dir()):
        fail(f"unsafe state directory: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
        metadata = path.lstat()
    except OSError as error:
        fail(f"cannot initialize state directory: {error}")
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        fail("state directory must be a private current-user directory")


def _env(name: str, *, required: bool = True) -> str:
    value = os.environ.get(name, "")
    if required and (not value or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        fail(f"required coordinate is missing: {name}")
    return value


def _coordinate(name: str, pattern: re.Pattern[str]) -> str:
    value = _env(name)
    if not pattern.fullmatch(value):
        fail(f"coordinate {name} has the wrong format")
    return value


def _config() -> Path:
    path = Path(_env("KIOKU_RELEASE_CONFIG_PATH")).absolute()
    _regular(path, private=True)
    return path


def _state_root() -> Path:
    root = Path(_env("XDG_STATE_HOME")).absolute()
    _private_directory(root)
    state = root / "enclave-release"
    _private_directory(state)
    return state


def _run(argv: Sequence[str], *, cwd: Path = ROOT, env: Mapping[str, str] | None = None, timeout: int = 3600) -> str:
    """Run a reviewed child command, forwarding no child stdout."""
    # Never inherit the adapter's ambient process environment.  Callers that
    # need a credential explicitly construct a separately reviewed env (gh or
    # gcloud); ordinary git/tag/push children receive only this base.
    child_env = dict(_base_child_env() if env is None else env)
    try:
        completed = subprocess.run(
            tuple(str(part) for part in argv),
            cwd=str(cwd),
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        fail(f"reviewed child command failed to start: {Path(str(argv[0])).name}")
    # Child stdout is a protocol of the child, not this adapter.  Keep it off
    # stdout and expose only bounded diagnostics on stderr.
    diagnostic = _redacted_diagnostic(completed.stderr)
    if completed.returncode != 0:
        if diagnostic:
            sys.stderr.write(diagnostic)
        fail(f"reviewed child command failed: {Path(str(argv[0])).name}")
    if diagnostic:
        sys.stderr.write(diagnostic)
    return completed.stdout


def _redacted_diagnostic(value: str) -> str:
    """Bound child diagnostics and remove credential values before logging."""
    redacted = value
    for name in (
        "KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY",
        "KIOKU_RELEASE_GITHUB_TOKEN",
        "KIOKU_RELEASE_GCP_READONLY_SERVICE_ACCOUNT",
        "GH_TOKEN",
    ):
        secret = os.environ.get(name)
        if secret:
            redacted = redacted.replace(secret, "<redacted>")
    if len(redacted) > 4096:
        redacted = redacted[-4096:]
    return redacted


def _base_child_env() -> dict[str, str]:
    """Return the non-secret environment allowed for reviewed children."""
    unexpected_git = sorted(
        name
        for name in os.environ
        if name.startswith("GIT_") and name not in SAFE_AMBIENT_GIT_ENV
    )
    if unexpected_git:
        fail("ambient Git overrides are not accepted: " + ", ".join(unexpected_git))
    if os.environ.get("GIT_NO_REPLACE_OBJECTS", "1") != "1":
        fail("GIT_NO_REPLACE_OBJECTS must be exactly 1 when supplied")
    environment = {
        name: value for name, value in os.environ.items()
        if name in {"PATH", "HOME", "XDG_STATE_HOME", "LC_ALL", "TMPDIR"}
    }
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def _owned_private_directory(path_value: str, label: str) -> Path:
    """Validate one dedicated, credential-free tool configuration directory."""
    path = Path(path_value)
    if not path.is_absolute() or ".." in path.parts:
        fail(f"{label} must be an absolute non-symlink path")
    try:
        metadata = path.lstat()
    except OSError:
        fail(f"{label} is missing")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail(f"{label} must be a current-user-owned mode-0700 directory")
    canonical = _canonical_path(path, label)
    path = canonical
    # The directory is an explicit credential-free boundary.  Reject links,
    # unsafe modes, and JSON fields that Docker credential helpers use.  Empty
    # directories are valid; Buildx creates its own non-secret metadata there.
    for directory, directories, files in os.walk(path, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in list(directories):
            child = directory_path / name
            try:
                child_metadata = child.lstat()
            except OSError:
                fail(f"{label} changed while it was checked")
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(child_metadata.st_mode) != 0o700
            ):
                fail(f"{label} contains an unsafe directory")
        for name in files:
            child = directory_path / name
            try:
                child_metadata = child.lstat()
            except OSError:
                fail(f"{label} changed while it was checked")
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISREG(child_metadata.st_mode)
                or child_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(child_metadata.st_mode) != 0o600
            ):
                fail(f"{label} contains an unsafe file")
            if child.suffix.lower() == ".json" or child.name == "config.json":
                try:
                    document = json.loads(child.read_bytes())
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    fail(f"{label} contains invalid JSON metadata")

                def check_json(value: Any) -> None:
                    if isinstance(value, dict):
                        for key, nested in value.items():
                            if str(key).replace("_", "").replace("-", "").lower() in CONFIG_SECRET_KEYS:
                                fail(f"{label} contains Docker credential material")
                            check_json(nested)
                    elif isinstance(value, list):
                        for nested in value:
                            check_json(nested)

                check_json(document)
    return path


def _owned_private_cloud_directory(path_value: str) -> Path:
    """Validate the explicit gcloud config boundary without parsing credentials."""
    path = Path(path_value)
    if not path.is_absolute() or ".." in path.parts:
        fail("CLOUDSDK_CONFIG must be an absolute non-repository path")
    try:
        metadata = path.lstat()
    except OSError:
        fail("CLOUDSDK_CONFIG is missing")
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        fail("CLOUDSDK_CONFIG must be a current-user-owned mode-0700 directory")
    canonical = _canonical_path(path, "CLOUDSDK_CONFIG")
    path = canonical
    try:
        path.resolve(strict=True).relative_to(ROOT.resolve(strict=True))
    except ValueError:
        pass
    else:
        fail("CLOUDSDK_CONFIG must be outside the source repository")
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
                fail("CLOUDSDK_CONFIG contains an unsafe directory")
        for name in files:
            child = parent / name
            child_metadata = child.lstat()
            if (
                stat.S_ISLNK(child_metadata.st_mode)
                or not stat.S_ISREG(child_metadata.st_mode)
                or child_metadata.st_uid != os.geteuid()
                or stat.S_IMODE(child_metadata.st_mode) != 0o600
            ):
                fail("CLOUDSDK_CONFIG contains an unsafe file")
    return path


def _owned_private_file(path_value: str, label: str) -> Path:
    path = Path(path_value)
    if not path.is_absolute() or ".." in path.parts:
        fail(f"{label} must be an absolute non-symlink path")
    _regular(path, private=True)
    canonical = _canonical_path(path, label)
    return canonical


def _known_hosts_has_fingerprint(payload: bytes, endpoint: str, expected: str) -> bool:
    """Require the endpoint's actual known-host key to match the pinned hash."""
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


def _native_child_env(*, include_cloud: bool) -> dict[str, str]:
    """Build the exact native-builder environment for the enclave pipeline.

    This is intentionally separate from the later publish credentials.  The
    build process receives only identity/transport pins and dedicated empty
    Docker/Buildx config directories; no Docker auth, credential helper,
    GitHub, signing, or cloud values can reach ``prepare``.
    """
    environment = _base_child_env()
    name = _env("KIOKU_NATIVE_BUILDER_NAME")
    builder_id = _env("KIOKU_NATIVE_BUILDER_ID")
    if not NATIVE_BUILDER_NAME.fullmatch(name) or not NATIVE_BUILDER_ID.fullmatch(builder_id):
        fail("native Buildx identity pin is malformed")
    endpoint = _env("DOCKER_HOST")
    if not TRANSPORT_ENDPOINT.fullmatch(endpoint):
        fail("native Buildx transport endpoint is malformed")
    if os.environ.get("DOCKER_CONTEXT"):
        fail("DOCKER_CONTEXT is not accepted; DOCKER_HOST is the pinned endpoint")
    environment.update({
        "KIOKU_NATIVE_BUILDER_NAME": name,
        "KIOKU_NATIVE_BUILDER_ID": builder_id,
        "DOCKER_HOST": endpoint,
    })
    for name_key in ("DOCKER_SSH_KNOWN_HOSTS", "DOCKER_SSH_HOST_KEY_SHA256", "DOCKER_SSH_COMMAND", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_BUILDER_CA_SHA256", "SSH_AUTH_SOCK"):
        if name_key in os.environ:
            value = os.environ[name_key]
            if any(ord(char) < 32 or ord(char) == 127 for char in value):
                fail(f"native Buildx coordinate contains a control character: {name_key}")
    if endpoint.startswith("ssh://"):
        known_hosts = _owned_private_file(_env("DOCKER_SSH_KNOWN_HOSTS"), "Docker SSH known-hosts file")
        host_key = _env("DOCKER_SSH_HOST_KEY_SHA256")
        if not SSH_HOST_KEY.fullmatch(host_key):
            fail("Docker SSH host-key pin is malformed")
        try:
            if not _known_hosts_has_fingerprint(known_hosts.read_bytes(), endpoint, host_key):
                fail("Docker SSH known-hosts file does not contain the pinned host key")
            tokens = shlex.split(_env("DOCKER_SSH_COMMAND"))
        except (OSError, UnicodeDecodeError, ValueError):
            fail("Docker SSH transport command is invalid")
        if not tokens or tokens[0] != "ssh":
            fail("Docker SSH transport must start with ssh")
        options: dict[str, str] = {}
        index = 1
        while index < len(tokens):
            if tokens[index] != "-o" or index + 1 >= len(tokens) or "=" not in tokens[index + 1]:
                fail("Docker SSH transport contains an unreviewed option")
            key, value = tokens[index + 1].split("=", 1)
            if key not in {"StrictHostKeyChecking", "UserKnownHostsFile"}:
                fail("Docker SSH transport contains an unreviewed option")
            options[key] = value
            index += 2
        if options != {"StrictHostKeyChecking": "yes", "UserKnownHostsFile": str(known_hosts)}:
            option_path = options.get("UserKnownHostsFile", "")
            if not option_path or not Path(option_path).is_absolute():
                fail("Docker SSH transport is not strict-host-key pinned")
            try:
                option_path = str(_canonical_path(Path(option_path), "Docker SSH known-hosts file"))
            except AdapterError:
                fail("Docker SSH transport is not strict-host-key pinned")
            if options.get("StrictHostKeyChecking") != "yes" or option_path != str(known_hosts):
                fail("Docker SSH transport is not strict-host-key pinned")
        environment["DOCKER_SSH_COMMAND"] = (
            f"ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts}"
        )
        if "SSH_AUTH_SOCK" in os.environ:
            try:
                socket_metadata = Path(os.environ["SSH_AUTH_SOCK"]).lstat()
            except OSError:
                fail("SSH_AUTH_SOCK is unavailable")
            if socket_metadata.st_uid != os.geteuid() or stat.S_IMODE(socket_metadata.st_mode) & 0o077:
                fail("SSH_AUTH_SOCK has unsafe ownership or permissions")
        environment.update({
            "DOCKER_SSH_KNOWN_HOSTS": str(known_hosts),
            "DOCKER_SSH_HOST_KEY_SHA256": host_key,
            "DOCKER_SSH_COMMAND": _env("DOCKER_SSH_COMMAND"),
        })
        if "SSH_AUTH_SOCK" in os.environ:
            environment["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    elif endpoint.startswith("tcp://"):
        if os.environ.get("DOCKER_TLS_VERIFY") != "1":
            fail("TLS native Buildx transport requires DOCKER_TLS_VERIFY=1")
        ca_hash = _env("DOCKER_BUILDER_CA_SHA256")
        if not HEX_HASH.fullmatch(ca_hash):
            fail("Docker builder CA pin is malformed")
        cert_path = _owned_private_directory(_env("DOCKER_CERT_PATH"), "Docker TLS certificate directory")
        for filename in ("ca.pem", "cert.pem", "key.pem"):
            _owned_private_file(str(cert_path / filename), f"Docker TLS {filename}")
        if hashlib.sha256((cert_path / "ca.pem").read_bytes()).hexdigest() != ca_hash:
            fail("Docker builder CA does not match its pinned digest")
        environment.update({
            "DOCKER_TLS_VERIFY": "1",
            "DOCKER_CERT_PATH": str(cert_path),
            "DOCKER_BUILDER_CA_SHA256": ca_hash,
        })
    else:
        if any(name_key in os.environ for name_key in ("DOCKER_SSH_KNOWN_HOSTS", "DOCKER_SSH_HOST_KEY_SHA256", "DOCKER_SSH_COMMAND", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_BUILDER_CA_SHA256", "SSH_AUTH_SOCK")):
            fail("unix native Buildx transport cannot carry SSH/TLS coordinates")
    docker_config = _owned_private_directory(_env("KIOKU_RELEASE_NATIVE_DOCKER_CONFIG"), "native Docker config directory")
    buildx_config = _owned_private_directory(_env("KIOKU_RELEASE_NATIVE_BUILDX_CONFIG"), "native Buildx config directory")
    environment.update({
        "DOCKER_CONFIG": str(docker_config),
        "BUILDX_CONFIG": str(buildx_config),
        # The direct pipeline revalidates these same paths before every child
        # subprocess; forwarding the reviewed source coordinates lets it keep
        # one environment boundary instead of trusting ambient config paths.
        "KIOKU_RELEASE_NATIVE_DOCKER_CONFIG": str(docker_config),
        "KIOKU_RELEASE_NATIVE_BUILDX_CONFIG": str(buildx_config),
    })
    if include_cloud:
        environment["CLOUDSDK_CONFIG"] = str(
            _owned_private_cloud_directory(_env("CLOUDSDK_CONFIG"))
        )
    return environment


def _git(*args: str, cwd: Path, timeout: int = 120) -> str:
    output = _run(
        ("git", "--no-replace-objects", "-C", str(cwd), *args),
        cwd=cwd,
        timeout=timeout,
    )
    return output.strip()


def _reject_git_replacement_objects(*, cwd: Path = ROOT) -> None:
    if _git("replace", "-l", cwd=cwd):
        fail("Git replacement refs are not accepted")
    graft_path = _git(
        "rev-parse", "--path-format=absolute", "--git-path", "info/grafts", cwd=cwd
    )
    if not graft_path or not Path(graft_path).is_absolute():
        fail("cannot resolve the repository graft-file path")
    if os.path.lexists(graft_path):
        fail("Git graft files are not accepted")


def _verify_frozen_source(commit: str, tree: str) -> None:
    _reject_git_replacement_objects()
    head = _git("rev-parse", "HEAD", cwd=ROOT)
    actual_tree = _git("rev-parse", "HEAD^{tree}", cwd=ROOT)
    if head != commit or actual_tree != tree:
        fail("adapter source is not the frozen commit/tree")


def _source_coordinates(*, verify_tag_ref: bool = True) -> tuple[str, str, str, str]:
    commit = _coordinate("KIOKU_RELEASE_SOURCE_COMMIT", COMMIT)
    tree = _coordinate("KIOKU_RELEASE_SOURCE_TREE", COMMIT)
    tag = _coordinate("KIOKU_RELEASE_TAG", TAG)
    version = _coordinate("KIOKU_RELEASE_VERSION", VERSION)
    _verify_frozen_source(commit, tree)
    if verify_tag_ref and _git(
        "rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}", cwd=ROOT
    ) != commit:
        fail("release tag does not resolve to the frozen commit")
    return commit, tree, tag, version


def _config_digest(path: Path) -> str:
    try:
        before = path.lstat()
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise OSError("configuration was replaced while opening")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            data = handle.read()
            after = os.fstat(handle.fileno())
        if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or len(data) != after.st_size:
            raise OSError("configuration changed while reading")
    except OSError as error:
        fail(f"cannot read release configuration: {error}")
    finally:
        if "descriptor" in locals() and descriptor >= 0:
            os.close(descriptor)
    return hashlib.sha256(data).hexdigest()


def _check_config_coordinate(path: Path) -> str:
    actual = _config_digest(path)
    expected = _coordinate("KIOKU_RELEASE_CONFIG_DIGEST", DIGEST)
    if "sha256:" + actual != expected:
        fail("release configuration changed after plan admission")
    return actual


def _artifact_root() -> Path:
    root = Path(_env("KIOKU_RELEASE_ARTIFACT_ROOT")).absolute()
    _private_directory(root)
    return root


def _output_dir(*, require_artifact_root: bool = True) -> Path:
    if require_artifact_root:
        output = _artifact_root() / "enclave-release" / "evidence"
    else:
        # State is read-only and may run without the coordinator's artifact
        # root. Keep its temporary downloads in the private XDG state area.
        output = _state_root() / "evidence"
    _private_directory(output)
    return output


def _state_relative(path: Path) -> str:
    """Return an artifact path relative to the coordinator artifact root."""
    root = _artifact_root().resolve()
    try:
        relative = path.resolve(strict=True).relative_to(root)
    except ValueError:
        fail("adapter output escaped the coordinator artifact root")
    if not relative.parts or ".." in relative.parts:
        fail("adapter output path is unsafe")
    return str(relative)


def _artifact_files(output: Path, paths: Sequence[Path]) -> list[dict[str, str]]:
    result: list[dict[str, str]] = []
    for path in paths:
        relative = _state_relative(path)
        try:
            data = _read_bound_file(path, label="adapter artifact")
        except (OSError, PipelineError) as error:
            fail(f"cannot read adapter artifact: {error}")
        result.append({"path": relative, "digest": "sha256:" + hashlib.sha256(data).hexdigest()})
    # The output contract is content-addressed and deterministic.
    return sorted(result, key=lambda item: item["path"])


def _read_bound_file(
    path: Path,
    *,
    label: str,
    mode: int = 0o600,
    expected_sha256: str | None = None,
    expected_manifest_digest: str | None = None,
) -> bytes:
    """Read one private file through a held descriptor and bind its bytes."""
    descriptor = _image_pipeline._open_owned(path, label, mode=mode)
    try:
        if expected_sha256 is not None and expected_manifest_digest is not None:
            _image_pipeline.verify_oci_archive_fd(
                descriptor,
                expected_sha256,
                expected_manifest_digest,
                mode=mode,
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            before = os.fstat(handle.fileno())
            data = handle.read()
            after = os.fstat(handle.fileno())
            if (
                before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or len(data) != after.st_size
            ):
                fail(f"{label} changed while it was read")
        actual = hashlib.sha256(data).hexdigest()
        if expected_sha256 is not None and actual != expected_sha256:
            fail(f"{label} no longer matches its immutable receipt")
        return data
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _pipeline(stage: str, config: Path, tag: str, output: Path) -> None:
    command = (
        sys.executable,
        str(PIPELINE),
        stage,
        "--config",
        str(config),
        "--profile",
        "production",
        "--source-ref",
        tag,
        "--output-dir",
        str(output),
        "--apply",
        "--resume",
    )
    # The untrusted build/scan child never receives signing or GitHub release
    # authority.  Push receives only the operator's short-lived GCP base
    # configuration needed to impersonate the config-pinned writer identity.
    child_environment = _native_child_env(include_cloud=stage == "push")
    _run(command, cwd=ROOT, env=child_environment, timeout=24 * 60 * 60)


def _read_json(path: Path, label: str) -> dict[str, Any]:
    _regular(path, private=True)
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value


def _receipt(output: Path, stage: str) -> dict[str, Any]:
    try:
        valid = _image_pipeline.stage_receipt_candidates(output, stage)
    except PipelineError as error:
        fail(str(error))
    if len(valid) != 1:
        fail(f"{stage} receipt is missing")
    payload = valid[0].get("outputs")
    if not isinstance(payload, dict):
        fail(f"{stage} receipt outputs are invalid")
    return payload


def _artifact(output: Path, *, stage: str = "build") -> tuple[Path, str, str]:
    values = _receipt(output, stage)
    path_value = values.get("artifact")
    artifact_hash = values.get("artifact_sha256")
    digest = values.get("artifact_manifest_digest")
    if not isinstance(path_value, str) or not isinstance(artifact_hash, str) or not isinstance(digest, str):
        fail("artifact receipt is incomplete")
    artifact = Path(path_value).absolute()
    if not DIGEST.fullmatch(digest) or not HEX_HASH.fullmatch(artifact_hash):
        fail("artifact receipt contains malformed hashes")
    try:
        artifact.resolve(strict=True).relative_to(_artifact_root().resolve(strict=True))
    except (OSError, ValueError):
        fail("artifact receipt escaped the coordinator artifact root")
    try:
        _read_bound_file(
            artifact,
            label="OCI artifact",
            expected_sha256=artifact_hash,
            expected_manifest_digest=digest,
        )
    except PipelineError as error:
        fail(str(error))
    return artifact, artifact_hash, digest


def _destination() -> str:
    value = _env("KIOKU_RELEASE_DESTINATION")
    if value != "enclave-artifact-registry-release":
        fail("enclave adapter destination is not the immutable registry release")
    return value


def _confirmation(version: str, digest: str) -> str:
    expected = f"PUBLISH ENCLAVE {version} {digest}"
    actual = _env("KIOKU_RELEASE_CONFIRMATION")
    if actual != expected:
        fail("publish confirmation does not bind exact version and artifact digest")
    return actual


def prepare() -> Mapping[str, Any]:
    commit, tree, tag, version = _source_coordinates()
    config = _config()
    _check_config_coordinate(config)
    output = _output_dir()
    # The pipeline itself has no cloud credential path for build: its cloud
    # preflight is selected only by push/preflight, and prepare receives no
    # later credential environment from the coordinator.
    _pipeline("build", config, tag, output)
    _verify_frozen_source(commit, tree)
    artifact_path, _artifact_hash, digest = _artifact(output)
    files = [artifact_path]
    for name in ("build-evidence.json", "enclave-sbom.spdx.json", "enclave-scan.json"):
        path = output / name
        if path.exists():
            files.append(path)
    return {
        "schema": SCHEMA,
        "status": "success",
        "artifact_digest": digest,
        "version": version,
        "artifact_files": _artifact_files(output, files),
    }


def _repository() -> str:
    return GITHUB_REPOSITORY


def _selected_configuration(config: Path, tag: str) -> tuple[dict[str, str], str]:
    try:
        configuration, account, _snapshot = configured_environment_snapshot(config, "production", tag)
    except PipelineError as error:
        fail(f"release configuration was rejected: {error}")
    return configuration, account


def _image_repository(config: Path, tag: str) -> tuple[str, str]:
    configuration, account = _selected_configuration(config, tag)
    value = (
        f"{configuration['REGION']}-docker.pkg.dev/{configuration['PROJECT_ID']}/"
        f"{configuration['AR_REPOSITORY']}/{configuration['IMAGE_NAME']}"
    )
    if not IMAGE_REPOSITORY.fullmatch(value):
        fail("Artifact Registry repository coordinate is malformed")
    return value, account


def _private_key(name: str) -> Path:
    path = Path(_env(name)).absolute()
    _regular(path, private=True)
    return path


def _public_key() -> tuple[Path, str]:
    path = Path(_env("KIOKU_RELEASE_EVIDENCE_PUBLIC_KEY")).absolute()
    _regular(path, mode=0o644)
    fingerprint = _coordinate("KIOKU_RELEASE_EVIDENCE_PUBLIC_KEY_SHA256", HASH)
    return path, fingerprint


def _sign_evidence(output: Path) -> None:
    private = _private_key("KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY")
    manifest = output / "enclave-local-build-evidence.json"
    signature = output / "enclave-local-build-evidence.sig"
    if signature.exists() or signature.is_symlink():
        _regular(signature, private=True)
    else:
        _run(
            (sys.executable, str(EVIDENCE), "sign", "--manifest", str(manifest), "--signature", str(signature), "--private-key", str(private)),
            cwd=ROOT,
            timeout=120,
        )
    _regular(signature, private=True)


def _verify_bundle(output: Path, config: Path, commit: str, tag: str, digest: str, *, image_repository: str) -> dict[str, Any]:
    public, fingerprint = _public_key()
    result = _run(
        (
            sys.executable,
            str(BUNDLE_VERIFY),
            "--evidence-dir",
            str(output),
            "--public-key",
            str(public),
            "--expected-public-key-sha256",
            fingerprint,
            "--repository",
            _repository(),
            "--tag",
            tag,
            "--commit",
            commit,
            "--image-repository",
            image_repository,
            "--image-digest-uri",
            f"{image_repository}@{digest}",
            "--image-digest",
            digest,
            "--config",
            str(config),
        ),
        cwd=ROOT,
        timeout=120,
    )
    try:
        value = json.loads(result)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"evidence verifier did not return JSON: {error}")
    if not isinstance(value, dict) or not isinstance(value.get("evidence"), dict):
        fail("evidence verifier returned an invalid result")
    return value


def _verify_tag_signer(tag_object: str) -> None:
    """Verify the captured object itself and match its pinned SSH/GPG signer."""
    expected = _env("KIOKU_RELEASE_TAG_SIGNER_FINGERPRINT")
    signer_environment = _base_child_env()
    if "GNUPGHOME" in os.environ:
        signer_environment["GNUPGHOME"] = os.environ["GNUPGHOME"]
    try:
        completed = subprocess.run(
            (
                "git", "--no-replace-objects", "verify-tag", "--raw", tag_object,
            ),
            cwd=str(ROOT),
            env=signer_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        fail("release tag signature verification could not run")
    if completed.returncode:
        fail("release tag object does not have a valid signature")
    verification = completed.stdout + "\n" + completed.stderr
    if expected.startswith("SHA256:"):
        if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]+={0,2}", expected):
            fail("tag signer fingerprint is malformed")
        actual = set(
            re.findall(r"\bkey (SHA256:[A-Za-z0-9+/]+={0,2})(?:\s|$)", verification)
        )
        if expected not in actual:
            fail("release tag signer does not match the pinned trust anchor")
        return
    fingerprint = expected.removeprefix("gpg:").upper()
    if not re.fullmatch(r"[0-9A-F]{16,64}", fingerprint):
        fail("tag signer fingerprint is malformed")
    actual: set[str] = set()
    for line in verification.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[:2] == ["[GNUPG:]", "VALIDSIG"]:
            actual.add(fields[2].upper())
            if len(fields) >= 12:
                actual.add(fields[-1].upper())
    if fingerprint not in actual:
        fail("release tag signer does not match the pinned trust anchor")


def _validate_tag_object(tag_object: str, tag: str, commit: str) -> None:
    if not COMMIT.fullmatch(tag_object):
        fail("release tag object ID is malformed")
    if _git("cat-file", "-t", tag_object, cwd=ROOT) != "tag":
        fail("release tag must be an annotated tag object")
    payload = _git("cat-file", "tag", tag_object, cwd=ROOT)
    header = payload.split("\n\n", 1)[0]
    names = [line.removeprefix("tag ") for line in header.splitlines() if line.startswith("tag ")]
    if names != [tag]:
        fail("signed annotated tag name does not exactly match the requested tag")
    if _git("rev-parse", f"{tag_object}^{{commit}}", cwd=ROOT) != commit:
        fail("signed annotated tag object does not peel to the frozen commit")


def _capture_verified_tag(tag: str, commit: str) -> VerifiedTag:
    """Resolve the mutable tag ref once, then trust only its immutable object ID."""
    _reject_git_replacement_objects()
    tag_object = _git(
        "rev-parse", "--verify", f"refs/tags/{tag}^{{tag}}", cwd=ROOT
    )
    _validate_tag_object(tag_object, tag, commit)
    _verify_tag_signer(tag_object)
    return VerifiedTag(tag, tag_object, commit)


def _revalidate_verified_tag(tag: VerifiedTag) -> None:
    _reject_git_replacement_objects()
    _validate_tag_object(tag.object_id, tag.name, tag.commit)
    _verify_tag_signer(tag.object_id)


def _verify_remote_tag_binding(tag: VerifiedTag) -> None:
    raw = _git(
        "ls-remote",
        "--tags",
        "origin",
        f"refs/tags/{tag.name}",
        f"refs/tags/{tag.name}^{{}}",
        cwd=ROOT,
        timeout=300,
    )
    actual: dict[str, str] = {}
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or not COMMIT.fullmatch(fields[0]) or fields[1] in actual:
            fail("remote tag readback is malformed or ambiguous")
        actual[fields[1]] = fields[0]
    expected = {
        f"refs/tags/{tag.name}": tag.object_id,
        f"refs/tags/{tag.name}^{{}}": tag.commit,
    }
    if actual != expected:
        fail("remote tag object or peeled commit differs from the verified tag")


def _gcloud_prefix(account: str) -> tuple[str, ...]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}@[A-Za-z0-9_.-]+", account):
        fail("read-only GCP service account is malformed")
    return (f"--impersonate-service-account={account}",)


def _registry_digest(repository: str, tag: str, account: str) -> str:
    image = f"{repository}:{tag}"
    value = _run(
        ("gcloud", *_gcloud_prefix(account), "artifacts", "docker", "images", "describe", image, "--format=value(image_summary.digest)"),
        cwd=ROOT,
        env=_gcloud_env(),
        timeout=120,
    ).strip()
    if not DIGEST.fullmatch(value):
        fail("Artifact Registry returned a non-immutable digest")
    return value


def _gh_env() -> dict[str, str]:
    environment = _base_child_env()
    token = os.environ.get("KIOKU_RELEASE_GITHUB_TOKEN")
    if token:
        environment["GH_TOKEN"] = token
    return environment


def _gh(*args: str, timeout: int = 120) -> str:
    return _run(("gh", *args), cwd=ROOT, env=_gh_env(), timeout=timeout)


def _github_release_absence(stderr: str) -> bool:
    """Recognize only gh's exact release-not-found responses."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    return len(lines) == 1 and lines[0] in {"release not found", "HTTP 404: Not Found"}


def _release_json(repository: str, tag: str) -> dict[str, Any] | None:
    try:
        completed = subprocess.run(
            ("gh", "release", "view", tag, "--repo", repository, "--json", "isDraft,isImmutable,isPrerelease,assets"),
            cwd=str(ROOT), env=_gh_env(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120, check=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        fail("GitHub release state command failed")
    if completed.returncode:
        if _github_release_absence(completed.stderr):
            return None
        diagnostic = _redacted_diagnostic(completed.stderr)
        if diagnostic:
            sys.stderr.write(diagnostic)
        fail("GitHub release state command was not a read-only successful query")
    raw = completed.stdout
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        fail(f"GitHub release state is not JSON: {error}")
    if not isinstance(value, dict):
        fail("GitHub release state is malformed")
    return value


def _gcloud_env() -> dict[str, str]:
    if os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        fail(
            "GOOGLE_APPLICATION_CREDENTIALS is not accepted by the enclave release adapter; use reviewed gcloud identity configuration"
        )
    environment = _base_child_env()
    environment["CLOUDSDK_CONFIG"] = str(
        _owned_private_cloud_directory(_env("CLOUDSDK_CONFIG"))
    )
    return environment


def _registry_digest_optional(repository: str, tag: str, account: str) -> str | None:
    """Read a registry tag, distinguishing an exact absence from an error."""
    image = f"{repository}:{tag}"
    try:
        completed = subprocess.run(
            (
                "gcloud",
                *_gcloud_prefix(account),
                "artifacts",
                "docker",
                "images",
                "describe",
                image,
                "--format=value(image_summary.digest)",
            ),
            cwd=str(ROOT),
            env=_gcloud_env(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        fail("Artifact Registry state command failed")
    if completed.returncode:
        lines = [line.strip() for line in completed.stderr.splitlines() if line.strip()]
        if len(lines) == 1 and re.fullmatch(
            r"ERROR:\s+\(gcloud\.artifacts\.docker\.images\.describe\)\s+NOT_FOUND:.*",
            lines[0],
            re.IGNORECASE,
        ):
            return None
        diagnostic = _redacted_diagnostic(completed.stderr)
        if diagnostic:
            sys.stderr.write(diagnostic)
        fail("Artifact Registry state command failed")
    value = completed.stdout.strip()
    if not value:
        fail("Artifact Registry returned an empty digest response")
    if not DIGEST.fullmatch(value):
        fail("Artifact Registry returned a non-immutable digest")
    return value


def _expected_assets(release: Mapping[str, Any], *, prerelease: bool) -> None:
    names = sorted(asset.get("name") for asset in release.get("assets", []) if isinstance(asset, Mapping))
    expected = sorted(_RELEASE_ASSET_NAMES)
    if release.get("isDraft") is not False or release.get("isImmutable") is not True or release.get("isPrerelease") is not prerelease or names != expected:
        fail("GitHub release is not the exact immutable enclave evidence release")


@contextmanager
def _immutable_release_snapshot(
    output: Path,
) -> Iterator[tuple[Path, dict[str, str]]]:
    """Snapshot every release asset once before verification and publication."""
    directory = Path(tempfile.mkdtemp(prefix=".verified-release-assets-", dir=str(output)))
    directory.chmod(0o700)
    digests: dict[str, str] = {}
    try:
        for name in _RELEASE_ASSET_NAMES:
            source = output / name
            data = _read_bound_file(source, label=f"release asset {name}")
            destination = directory / name
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                view = memoryview(data)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        fail(f"cannot snapshot release asset: {name}")
                    view = view[written:]
                os.fsync(descriptor)
                os.fchmod(descriptor, 0o400)
            finally:
                os.close(descriptor)
            digests[name] = "sha256:" + hashlib.sha256(data).hexdigest()
        directory_descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        directory.chmod(0o500)
        yield directory, digests
    except OSError as error:
        fail(f"cannot create immutable release-asset snapshot: {error}")
    finally:
        try:
            directory.chmod(0o700)
        except OSError:
            pass
        for name in _RELEASE_ASSET_NAMES:
            path = directory / name
            try:
                path.chmod(0o600)
                path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
        try:
            directory.rmdir()
        except OSError:
            pass


def _compare_published_assets(output: Path, repository: str, tag: str) -> None:
    """Prove an existing immutable release contains the exact prepared bytes.

    GitHub's asset metadata is not sufficient evidence for a retry: an asset
    list can be complete while an individual payload is stale or replaced.
    Download every expected asset through the reviewed CLI and compare its
    bytes to the private prepared evidence before accepting the release.
    """
    downloaded = _download_release(output, repository, tag)
    try:
        for name in _RELEASE_ASSET_NAMES:
            local = output / name
            remote = downloaded / name
            try:
                local_bytes = _read_bound_file(
                    local, label=f"snapshotted release asset {name}", mode=0o400
                )
                remote_bytes = _read_bound_file(
                    remote, label=f"downloaded release asset {name}"
                )
            except PipelineError as error:
                fail(str(error))
            if local_bytes != remote_bytes:
                fail(f"immutable GitHub asset differs from the prepared evidence: {name}")
    finally:
        shutil.rmtree(downloaded, ignore_errors=True)


def _publish_release(
    output: Path, repository: str, tag: VerifiedTag, digest: str
) -> None:
    _revalidate_verified_tag(tag)
    enabled = _gh("api", "-H", "X-GitHub-Api-Version: 2026-03-10", f"repos/{repository}/immutable-releases", "--jq", ".enabled").strip()
    if enabled != "true":
        fail("GitHub immutable releases are not enabled")
    # Push exactly the verified annotated-tag object. Never resolve its mutable
    # local name again, including on resume.
    _git(
        "push",
        "origin",
        f"{tag.object_id}:refs/tags/{tag.name}",
        cwd=ROOT,
        timeout=300,
    )
    _verify_remote_tag_binding(tag)
    current = _release_json(repository, tag.name)
    prerelease = not bool(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag.name))
    if current is None:
        notes = f"Kioku enclave {tag.name}\nSource commit: {tag.commit}\nImage digest: {digest}\n"
        with tempfile.NamedTemporaryFile("w", prefix="release-notes-", suffix=".txt", delete=False) as handle:
            handle.write(notes)
            notes_path = Path(handle.name)
        try:
            command = ["release", "create", tag.name, *(str(output / name) for name in _RELEASE_ASSET_NAMES), "--repo", repository, "--verify-tag", "--title", f"Kioku enclave {tag.name}", "--notes-file", str(notes_path)]
            if prerelease:
                command.append("--prerelease")
            _gh(*command, timeout=300)
        finally:
            try:
                notes_path.unlink()
            except OSError:
                pass
        current = _release_json(repository, tag.name)
    if current is None:
        fail("GitHub release disappeared after publication")
    _expected_assets(current, prerelease=prerelease)
    _compare_published_assets(output, repository, tag.name)
    _verify_remote_tag_binding(tag)


def publish() -> Mapping[str, Any]:
    # Publication resolves the mutable tag ref only once in
    # ``_capture_verified_tag`` below; every later step uses that object ID.
    commit, tree, tag, version = _source_coordinates(verify_tag_ref=False)
    config = _config()
    _check_config_coordinate(config)
    output = _output_dir()
    # Validate all trust anchors and later credentials before the pipeline can
    # request its short-lived push identity or change Artifact Registry.
    _private_key("KIOKU_RELEASE_EVIDENCE_PRIVATE_KEY")
    _public_key()
    repository = _repository()
    image_repository, registry_reader = _image_repository(config, tag)
    verified_tag = _capture_verified_tag(tag, commit)
    _pipeline("push", config, tag, output)
    _verify_frozen_source(commit, tree)
    _revalidate_verified_tag(verified_tag)
    values = _receipt(output, "push")
    digest = values.get("image_digest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        fail("push receipt has no immutable image digest")
    expected = _coordinate("KIOKU_RELEASE_ARTIFACT_DIGEST", DIGEST)
    if digest != expected:
        fail("pushed image digest differs from the frozen candidate")
    # The remote promotion must preserve the exact local OCI manifest selected
    # by prepare; the plan digest alone is not sufficient if a stale receipt
    # was accidentally resumed.
    _artifact_path, _artifact_hash, local_manifest_digest = _artifact(output)
    if local_manifest_digest != digest:
        fail("remote image digest differs from the local artifact manifest")
    _sign_evidence(output)
    with _immutable_release_snapshot(output) as (release_assets, release_hashes):
        _verify_bundle(
            release_assets,
            config,
            commit,
            tag,
            digest,
            image_repository=image_repository,
        )
        if _registry_digest(image_repository, tag, registry_reader) != digest:
            fail("Artifact Registry digest differs from the signed candidate")
        _confirmation(version, digest)
        _publish_release(release_assets, repository, verified_tag, digest)
        files = [output / name for name in _RELEASE_ASSET_NAMES]
        # The OCI archive's filename is executor-owned; include it from the
        # build receipt as well as the immutable release assets.
        artifact_path = _artifact_path
        files.append(artifact_path)
        artifacts = _artifact_files(output, files)
        actual_release_hashes = {
            Path(item["path"]).name: item["digest"]
            for item in artifacts
            if Path(item["path"]).name in _RELEASE_ASSET_NAMES
        }
        if actual_release_hashes != release_hashes:
            fail("prepared release assets changed after their immutable snapshot")
        result = {
            "schema": SCHEMA,
            "status": "success",
            "artifact_digest": digest,
            "version": version,
            "destination": _destination(),
            "artifact_files": artifacts,
        }
    return result


def verify() -> Mapping[str, Any]:
    commit, _tree, tag, version = _source_coordinates()
    config = _config()
    _check_config_coordinate(config)
    output = _output_dir()
    values = _receipt(output, "push")
    digest = values.get("image_digest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        fail("publish receipt has no immutable image digest")
    image_repository, _registry_reader = _image_repository(config, tag)
    _verify_bundle(output, config, commit, tag, digest, image_repository=image_repository)
    files = [output / name for name in _RELEASE_ASSET_NAMES]
    return {"schema": SCHEMA, "status": "success", "artifact_digest": digest, "version": version, "artifact_files": _artifact_files(output, files)}


def _download_release(output: Path, repository: str, tag: str) -> Path:
    directory = Path(tempfile.mkdtemp(prefix="state-evidence-", dir=str(output.parent)))
    directory.chmod(0o700)
    _private_directory(directory)
    for name in _RELEASE_ASSET_NAMES:
        _gh("release", "download", tag, "--repo", repository, "--pattern", name, "--dir", str(directory), timeout=300)
        downloaded = directory / name
        _regular(downloaded, private=False)
        downloaded.chmod(0o600)
        _regular(downloaded, private=True)
    return directory


def state(destination: str) -> Mapping[str, Any]:
    if destination != "enclave-artifact-registry-release":
        fail("unknown enclave state destination")
    commit = _coordinate("KIOKU_RELEASE_SOURCE_COMMIT", COMMIT)
    _tree, tag, version = _source_coordinates()[1:]
    config = _config()
    _check_config_coordinate(config)
    repository = _repository()
    image_repository, registry_reader = _image_repository(config, tag)
    # A candidate tag may legitimately have no immutable release yet.  Return
    # an explicit absent state so the coordinator can distinguish “not
    # published” from a malformed or partially published release.
    release = _release_json(repository, tag)
    if release is None:
        registry_digest = _registry_digest_optional(image_repository, tag, registry_reader)
        if registry_digest is not None:
            fail("Artifact Registry contains the candidate tag but no immutable evidence release exists")
        return {
            "schema": STATE_SCHEMA,
            "status": "success",
            "destination": destination,
            "state": {"version": version, "artifact_digest": ZERO_DIGEST, "present": False},
        }
    output = _output_dir(require_artifact_root=False)
    evidence_dir = _download_release(output, repository, tag)
    metadata = _read_json(evidence_dir / "enclave-release.json", "release metadata")
    digest = metadata.get("image_digest")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        fail("release metadata has no immutable image digest")
    _verify_bundle(evidence_dir, config, commit, tag, digest, image_repository=image_repository)
    registry_digest = _registry_digest(image_repository, tag, registry_reader)
    if registry_digest != digest:
        fail("Artifact Registry and immutable GitHub evidence disagree")
    _expected_assets(release, prerelease=not bool(re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag)))
    if metadata.get("source_ref") != tag or metadata.get("source_commit") != commit:
        fail("immutable release evidence does not bind the frozen source")
    return {
        "schema": STATE_SCHEMA,
        "status": "success",
        "destination": destination,
        "state": {"version": version, "artifact_digest": digest, "present": True},
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "publish", "verify", "state"))
    parser.add_argument("destination", nargs="?")
    parser.add_argument("--confirm", dest="confirmation")
    arguments = parser.parse_args(argv)
    if arguments.confirmation is not None:
        os.environ["KIOKU_RELEASE_CONFIRMATION"] = arguments.confirmation
    try:
        if arguments.command == "prepare":
            result = prepare()
        elif arguments.command == "publish":
            result = publish()
        elif arguments.command == "verify":
            result = verify()
        else:
            if arguments.destination is None:
                fail("state destination is required")
            result = state(arguments.destination)
        emit(result)
        return 0
    except AdapterError as error:
        sys.stderr.write(f"enclave release adapter: {error}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
