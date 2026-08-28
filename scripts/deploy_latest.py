#!/usr/bin/env python3
"""Build, sign, and publish the Cargo-versioned enclave release."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")


class ReleaseTagError(RuntimeError):
    pass


def run(command: list[str], *, environment: dict[str, str] | None = None) -> None:
    completed = subprocess.run(command, cwd=ROOT, env=environment, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def git_output(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", "--no-replace-objects", *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise SystemExit("deploy-latest: Git source validation failed")
    return completed.stdout.strip()


def cargo_version() -> str:
    try:
        document = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
        version = document["package"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseTagError("Cargo package version is unavailable") from error
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise ReleaseTagError("Cargo package version is not canonical semantic versioning")
    return version


def checked_tag(*, allow_existing: bool) -> str:
    tag = f"v{cargo_version()}"
    completed = subprocess.run(
        ["git", "--no-replace-objects", "ls-remote", "--tags", "origin", f"refs/tags/{tag}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise ReleaseTagError("could not inspect the remote release tag")
    if completed.stdout.strip() and not allow_existing:
        raise ReleaseTagError("Cargo version already has a remote release tag; bump it first")
    return tag


def ensure_release_source(tag: str, signing_key: Path) -> None:
    if not signing_key.is_file():
        raise SystemExit("deploy-latest: tag signing key is not a regular file")
    signing_key = signing_key.resolve()
    if git_output("status", "--porcelain"):
        raise SystemExit("deploy-latest: source checkout is not clean")
    head = git_output("rev-parse", "HEAD")
    if head != git_output("rev-parse", "origin/main"):
        raise SystemExit("deploy-latest: source must equal the newest merged main")
    existing = subprocess.run(
        ["git", "--no-replace-objects", "rev-parse", "--verify", f"refs/tags/{tag}^{{tag}}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if existing.returncode != 0:
        run(
            [
                "git",
                "--no-replace-objects",
                "-c",
                "gpg.format=ssh",
                "-c",
                f"user.signingkey={signing_key}",
                "tag",
                "-s",
                tag,
                "-m",
                f"Kioku enclave {tag}",
                head,
            ]
        )
    if git_output("rev-parse", f"refs/tags/{tag}^{{commit}}") != head:
        raise SystemExit("deploy-latest: signed release tag does not peel to main")


def pipeline_command(arguments: argparse.Namespace, tag: str) -> list[str]:
    command = [
        sys.executable,
        str(ROOT / "scripts/local_image_pipeline.py"),
        arguments.stage,
        "--config",
        str(arguments.config),
        "--profile",
        "production",
        "--source-ref",
        tag,
    ]
    if arguments.output_dir is not None:
        command.extend(("--output-dir", str(arguments.output_dir)))
    if arguments.apply:
        command.append("--apply")
    if arguments.resume:
        command.append("--resume")
    return command


def sign_or_verify(arguments: argparse.Namespace) -> None:
    manifest = arguments.output_dir / "enclave-local-build-evidence.json"
    signature = arguments.output_dir / "enclave-local-build-evidence.sig"
    if signature.exists():
        run(
            [
                sys.executable,
                str(ROOT / "scripts/local_build_evidence.py"),
                "verify",
                "--manifest",
                str(manifest),
                "--signature",
                str(signature),
                "--public-key",
                str(arguments.evidence_public_key),
                "--expected-public-key-sha256",
                arguments.evidence_public_key_sha256,
            ]
        )
    else:
        run(
            [
                sys.executable,
                str(ROOT / "scripts/local_build_evidence.py"),
                "sign",
                "--manifest",
                str(manifest),
                "--signature",
                str(signature),
                "--private-key",
                str(arguments.evidence_private_key),
            ]
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("tag", help="print the Cargo-versioned release tag")

    pipeline = subparsers.add_parser("pipeline", help="run a tag-derived image stage")
    pipeline.add_argument("stage", choices=("preflight", "verify", "build", "push"))
    pipeline.add_argument("--config", type=Path, required=True)
    pipeline.add_argument("--output-dir", type=Path)
    pipeline.add_argument("--apply", action="store_true")
    pipeline.add_argument("--resume", action="store_true")
    pipeline.add_argument("--tag-signing-key", type=Path)

    release = subparsers.add_parser("release", help="build, push, sign, and publish")
    release.add_argument("--config", type=Path, required=True)
    release.add_argument("--output-dir", type=Path, required=True)
    release.add_argument("--repository", required=True)
    release.add_argument("--evidence-private-key", type=Path, required=True)
    release.add_argument("--evidence-public-key", type=Path, required=True)
    release.add_argument("--evidence-public-key-sha256", required=True)
    release.add_argument("--release-signer-fingerprint", required=True)
    release.add_argument("--tag-signing-key", type=Path, required=True)
    arguments = parser.parse_args()

    try:
        tag = checked_tag(allow_existing=arguments.command in ("tag", "release"))
    except ReleaseTagError as error:
        print(f"deploy-latest: {error}", file=sys.stderr)
        return 1
    if arguments.command == "tag":
        print(tag)
        return 0
    if arguments.command == "release" or arguments.stage in ("build", "push"):
        if arguments.tag_signing_key is None:
            parser.error("build and push require --tag-signing-key")
        ensure_release_source(tag, arguments.tag_signing_key)
    if arguments.command == "pipeline":
        run(pipeline_command(arguments, tag))
        return 0

    arguments.stage = "push"
    arguments.apply = True
    arguments.resume = True
    run(pipeline_command(arguments, tag))
    sign_or_verify(arguments)
    environment = os.environ | {
        "RELEASE_SIGNER_FINGERPRINT": arguments.release_signer_fingerprint,
        "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY": str(arguments.evidence_public_key),
        "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256": arguments.evidence_public_key_sha256,
    }
    run(
        [
            str(ROOT / "scripts/release.sh"),
            tag,
            "--evidence-dir",
            str(arguments.output_dir),
            "--config",
            str(arguments.config),
            "--repository",
            arguments.repository,
            "--apply",
        ],
        environment=environment,
    )
    print(tag)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
