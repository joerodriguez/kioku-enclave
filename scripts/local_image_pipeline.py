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
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

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
CONFIG_NAME = re.compile(r"[A-Z][A-Z0-9_]*\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
DIGEST_IN_OUTPUT = re.compile(r"sha256:[0-9a-f]{64}")
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


def run(
    command: list[str],
    *,
    capture: bool = False,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a fixed argv command without a shell or inherited configuration output."""
    child_environment = None
    if environment is not None:
        child_environment = os.environ.copy()
        child_environment.update(environment)
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=child_environment,
        text=True,
        capture_output=capture,
        check=False,
    )
    if completed.returncode:
        if capture and completed.stderr:
            raise PipelineError(completed.stderr.strip())
        raise PipelineError("command failed: " + " ".join(command[:3]))
    return completed


def read_operator_config(path: Path) -> dict[str, str]:
    """Read an exact KEY=VALUE file without evaluating it as shell code."""
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
        try:
            with os.fdopen(descriptor, encoding="utf-8") as handle:
                lines = handle.read().splitlines()
            descriptor = -1
        except UnicodeDecodeError as error:
            raise PipelineError("operator configuration must be UTF-8 text") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

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


def configured_environment(
    config_path: Path, profile: str, source_ref: str
) -> tuple[dict[str, str], str]:
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

    operator_config = read_operator_config(config_path)
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
    return configuration, impersonated_account


def parse_exact_version(output: str, tool: str, expected: str) -> None:
    if expected not in output:
        raise PipelineError(f"{tool} version must include {expected}")


def preflight_tools(*, need_cloud: bool) -> None:
    parse_exact_version(run(["docker", "buildx", "version"], capture=True).stdout, "docker buildx", "buildx")
    builder = run(["docker", "buildx", "inspect", "--bootstrap"], capture=True).stdout
    platforms = re.search(r"(?m)^Platforms:\s*(.+)$", builder)
    if platforms is None or "linux/amd64" not in {
        platform.strip() for platform in platforms.group(1).split(",")
    }:
        raise PipelineError("Docker Buildx must advertise the exact linux/amd64 platform")
    parse_exact_version(run(["syft", "--version"], capture=True).stdout, "syft", SYFT_VERSION)
    parse_exact_version(run(["grype", "--version"], capture=True).stdout, "grype", GRYPE_VERSION)
    if need_cloud:
        parse_exact_version(run(["gcloud", "version"], capture=True).stdout, "gcloud", GCLOUD_VERSION)


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


@contextmanager
def source_snapshot(commit: str):
    """Yield a Docker context materialized only from the attested Git commit."""
    with tempfile.TemporaryDirectory(prefix="kioku-source-") as temporary:
        directory = Path(temporary)
        archive = directory / "source.tar"
        context = directory / "context"
        context.mkdir(mode=0o700)
        run(["git", "archive", "--format=tar", f"--output={archive}", commit])
        try:
            with tarfile.open(archive, mode="r:") as source:
                source.extractall(context, filter="data")
        except (OSError, tarfile.TarError) as error:
            raise PipelineError("could not materialize the immutable source snapshot") from error
        archive.unlink()
        yield context


def verify() -> None:
    """Run every former CI test/format/lint/audit gate in the former order."""
    contract_tests = (
        "test_agent_verify.py",
        "test_rust_build_lifecycle.py",
        "test_bootstrap_local_operator_config.py",
        "test_archive_witness_probe_config.py",
        "test_archive_v3_shadow_runtime_config.py",
        "test_select_build_configuration.py",
        "test_local_build_evidence.py",
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


def docker_build_arguments(configuration: dict[str, str], profile: str, source_date_epoch: int) -> list[str]:
    argument_names = (
        ("SOURCE_DATE_EPOCH", str(source_date_epoch)),
        ("KIOKU_BUILD_PROFILE", profile),
        ("KMS_PROJECT", configuration["ENCLAVE_KMS_PROJECT"]),
        ("KMS_LOCATION", configuration["ENCLAVE_KMS_LOCATION"]),
        ("KMS_KEY_RING", configuration["ENCLAVE_KMS_KEY_RING"]),
        ("KMS_KEY", configuration["ENCLAVE_KMS_KEY"]),
        ("GCS_BUCKET", configuration["ENCLAVE_GCS_BUCKET"]),
        ("GCS_MEDIA_BUCKET", configuration["ENCLAVE_GCS_MEDIA_BUCKET"]),
        ("GCS_LEGACY_MEDIA_BUCKET", configuration["ENCLAVE_GCS_LEGACY_MEDIA_BUCKET"]),
        ("ARCHIVE_WITNESS_SHADOW_MODE", configuration["ARCHIVE_WITNESS_SHADOW_MODE"]),
        ("ARCHIVE_WITNESS_PROJECT_ID", configuration["ARCHIVE_WITNESS_PROJECT_ID"]),
        ("ARCHIVE_WITNESS_PROJECT_NUMBER", configuration["ARCHIVE_WITNESS_PROJECT_NUMBER"]),
        ("ARCHIVE_WITNESS_DATABASE_ID", configuration["ARCHIVE_WITNESS_DATABASE_ID"]),
        ("ARCHIVE_V3_SHADOW_RUNTIME_MODE", configuration["ARCHIVE_V3_SHADOW_RUNTIME_MODE"]),
        ("ARCHIVE_V3_ARCHIVE_BUCKET", configuration["ARCHIVE_V3_ARCHIVE_BUCKET"]),
        ("ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER", configuration["ARCHIVE_V3_ARCHIVE_GCS_PROJECT_NUMBER"]),
        ("ARCHIVE_V3_REGISTRY_KMS_VERSION", configuration["ARCHIVE_V3_REGISTRY_KMS_VERSION"]),
        ("ARCHIVE_V3_WITNESS_PROJECT_ID", configuration["ARCHIVE_V3_WITNESS_PROJECT_ID"]),
        ("ARCHIVE_V3_WITNESS_PROJECT_NUMBER", configuration["ARCHIVE_V3_WITNESS_PROJECT_NUMBER"]),
        ("ARCHIVE_V3_WITNESS_DATABASE_ID", configuration["ARCHIVE_V3_WITNESS_DATABASE_ID"]),
        ("ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT", configuration["ARCHIVE_V3_ARCHIVE_BINDING_COMMITMENT"]),
        ("RUN_SA_EMAIL", configuration["ENCLAVE_RUN_SA_EMAIL"]),
        ("ENCLAVE_AUDIENCE", configuration["ENCLAVE_AUDIENCE"]),
        ("ATTEST_STS_AUDIENCE", configuration["ENCLAVE_ATTEST_STS_AUDIENCE"]),
        ("GOOGLE_DESKTOP_CLIENT_ID", configuration["GOOGLE_DESKTOP_CLIENT_ID"]),
        ("GOOGLE_IOS_CLIENT_ID", configuration["GOOGLE_IOS_CLIENT_ID"]),
        ("GOOGLE_WEB_CLIENT_ID", configuration["GOOGLE_WEB_CLIENT_ID"]),
        ("APPLE_TEAM_ID", configuration["APPLE_TEAM_ID"]),
        ("APPLE_KEY_ID", configuration["APPLE_KEY_ID"]),
        ("APPLE_IOS_CLIENT_ID", configuration["APPLE_IOS_CLIENT_ID"]),
        ("APPLE_MACOS_CLIENT_ID", configuration["APPLE_MACOS_CLIENT_ID"]),
        ("APPLE_WEB_CLIENT_ID", configuration["APPLE_WEB_CLIENT_ID"]),
        ("APNS_TEAM_ID", configuration["APNS_TEAM_ID"]),
        ("APNS_PRODUCTION_KEY_ID", configuration["APNS_PRODUCTION_KEY_ID"]),
        ("APNS_SANDBOX_KEY_ID", configuration["APNS_SANDBOX_KEY_ID"]),
        ("ALLOWED_EMAILS", configuration["ALLOWED_EMAILS"]),
        ("ADMIN_USER_IDS", configuration["ADMIN_USER_IDS"]),
        ("BASE_URL", configuration["BASE_URL"]),
        ("WEB_ORIGIN", configuration["WEB_ORIGIN"]),
        ("BILLING_SERVICE_URL", configuration["BILLING_SERVICE_URL"]),
        ("BILLING_SERVICE_AUDIENCE", configuration["BILLING_SERVICE_AUDIENCE"]),
        ("BILLING_ENFORCEMENT_MODE", configuration["BILLING_ENFORCEMENT_MODE"]),
        ("REVIEWER_AUTH_API_KEY", configuration["REVIEWER_AUTH_API_KEY"]),
        ("REVIEWER_AUTH_UID", configuration["REVIEWER_AUTH_UID"]),
        ("REVIEWER_AUTH_EMAIL", configuration["REVIEWER_AUTH_EMAIL"]),
        ("VERTEX_PROJECT", configuration["VERTEX_PROJECT"]),
        ("VERTEX_LOCATION", configuration["VERTEX_LOCATION"]),
        ("VERTEX_MODEL", configuration["VERTEX_MODEL"]),
        ("ENCLAVE_ACME", configuration["ENCLAVE_ACME"]),
        ("ENCLAVE_ACME_DIRECTORY", configuration["ENCLAVE_ACME_DIRECTORY"]),
        ("ENCLAVE_ACME_CONTACT", configuration["ENCLAVE_ACME_CONTACT"]),
    )
    result: list[str] = []
    for name, value in argument_names:
        result.extend(["--build-arg", f"{name}={value}"])
    return result


def write_evidence(path: Path, evidence: dict[str, object]) -> None:
    path.write_text(json.dumps(evidence, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


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


def sbom_and_scan(image_uri: str, output_dir: Path) -> None:
    sbom_path = output_dir / "enclave-sbom.spdx.json"
    run(
        ["syft", f"docker:{image_uri}", "-o", f"spdx-json={sbom_path}"],
        environment={"DOCKER_HOST": active_docker_host()},
    )
    try:
        sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineError("syft did not produce a valid SPDX JSON SBOM") from error
    package_names = {package.get("name", "").lower() for package in sbom.get("packages", [])}
    missing = sorted(REQUIRED_SBOM_PACKAGES - package_names)
    if missing:
        raise PipelineError("SBOM is missing auditable Rust packages: " + ", ".join(missing))
    # Capture only scan output, never selected configuration or credentials.
    scan = run(
        ["grype", f"sbom:{sbom_path}", "--only-fixed", "--fail-on", "high", "-o", "json"],
        capture=True,
    )
    (output_dir / "enclave-scan.json").write_text(scan.stdout, encoding="utf-8")


def create_release_evidence(
    output_dir: Path,
    *,
    config_path: Path,
    source_ref: str,
    source_commit: str,
    image_uri: str,
    image_digest: str,
    created_at: str,
) -> None:
    tag = release_tag(source_ref)
    if tag is None:
        return
    if not image_uri or not DIGEST.fullmatch(image_digest):
        raise PipelineError("release evidence requires an immutable image digest")
    repository = source_repository()
    owner_repository = repository.removeprefix("https://github.com/")
    metadata_path = output_dir / "enclave-release.json"
    configuration, _ = configured_environment(config_path, "production", source_ref)
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
    metadata_path.write_text(json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
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
        for line in run(["gcloud", "version"], capture=True).stdout.splitlines()
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
        "--dockerfile", str(ROOT / "Dockerfile"),
        "--cargo-lock", str(ROOT / "Cargo.lock"),
        "--release-metadata", str(metadata_path),
        "--sbom", str(output_dir / "enclave-sbom.spdx.json"),
        "--scan", str(output_dir / "enclave-scan.json"),
        "--created-at", created_at,
        "--completed-at", completed_at,
    ]
    for name, version in versions.items():
        command.extend(["--tool-version", f"{name}={version}"])
    run(command)


def temporary_docker_login(registry: str, docker_config: Path, access_token: str) -> None:
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
    )
    if login.returncode:
        raise PipelineError("temporary Docker login with the builder identity failed")


def authenticate_and_push(
    image_uri: str, configuration: dict[str, str], impersonated_account: str
) -> str:
    gcloud_prefix = ["gcloud", f"--impersonate-service-account={impersonated_account}"]
    registry = f"{configuration['REGION']}-docker.pkg.dev"
    docker_host = active_docker_host()
    access_token = run(
        gcloud_prefix + ["auth", "print-access-token"], capture=True
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
        access_token = ""
        pushed = run(
            ["docker", "--config", str(docker_config), "push", image_uri],
            capture=True,
            environment={"DOCKER_HOST": docker_host},
        )
    matches = DIGEST_IN_OUTPUT.findall(pushed.stdout + "\n" + pushed.stderr)
    if not matches:
        raise PipelineError("docker push did not return an immutable image digest")
    digest = matches[-1]
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
    ).stdout.strip()
    if not DIGEST.fullmatch(registry_digest) or registry_digest != digest:
        raise PipelineError("registry digest mismatch for the pushed image")
    return digest


def require_apply(stage: str, apply: bool) -> None:
    if stage != "preflight" and not apply:
        raise PipelineError(f"{stage} changes local or remote state; rerun with --apply")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the local enclave CI/image pipeline without GitHub Actions."
    )
    parser.add_argument("stage", nargs="?", choices=("preflight", "verify", "build", "push"), default="preflight")
    parser.add_argument("--config", type=Path, required=True, help="external mode-0600 KEY=VALUE operator configuration")
    parser.add_argument("--profile", choices=("production", "evaluation"), default="production")
    parser.add_argument("--source-ref", default="HEAD")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--apply", action="store_true", help="acknowledge local/remote state changes")
    arguments = parser.parse_args()

    try:
        if (
            arguments.source_ref.startswith("v")
            or arguments.source_ref.startswith("refs/tags/v")
        ) and arguments.profile != "production":
            raise PipelineError("release tags may only build the production profile")
        configuration, impersonated_account = configured_environment(
            arguments.config, arguments.profile, arguments.source_ref
        )
        require_apply(arguments.stage, arguments.apply)
        preflight_tools(need_cloud=arguments.stage in ("preflight", "push"))
        if arguments.stage == "preflight":
            print("local enclave pipeline preflight passed; no build, authentication, or push occurred")
            return
        verify()
        if arguments.stage == "verify":
            print("local enclave verification passed")
            return
        if arguments.output_dir is None:
            raise PipelineError("build and push require --output-dir for unsigned evidence")
        output_dir = arguments.output_dir.resolve()
        output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        commit, source_date_epoch = source_commit(arguments.source_ref)
        created_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        repository, image_uri = image_coordinates(
            configuration, arguments.profile, commit, arguments.source_ref
        )
        with source_snapshot(commit) as snapshot:
            run(
                [
                    "docker",
                    "buildx",
                    "build",
                    "--platform",
                    "linux/amd64",
                    "--load",
                    "--tag",
                    image_uri,
                    *docker_build_arguments(configuration, arguments.profile, source_date_epoch),
                    str(snapshot),
                ]
            )
        sbom_and_scan(image_uri, output_dir)
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
            "source_ref": arguments.source_ref,
            "sbom": "enclave-sbom.spdx.json",
            "scan": "enclave-scan.json",
            "config_sha256": sha256(arguments.config),
            "dockerfile_sha256": sha256(ROOT / "Dockerfile"),
            "cargo_lock_sha256": sha256(ROOT / "Cargo.lock"),
            "created_at": created_at,
            "signed": False,
        }
        if arguments.stage == "push":
            evidence["image_digest"] = authenticate_and_push(
                image_uri, configuration, impersonated_account
            )
            create_release_evidence(
                output_dir,
                config_path=arguments.config,
                source_ref=arguments.source_ref,
                source_commit=commit,
                image_uri=image_uri,
                image_digest=str(evidence["image_digest"]),
                created_at=created_at,
            )
        evidence["completed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        write_evidence(output_dir / "build-evidence.json", evidence)
        print(f"unsigned build evidence written to {output_dir}")
    except PipelineError as error:
        print(f"local image pipeline: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
