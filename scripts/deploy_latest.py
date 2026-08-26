#!/usr/bin/env python3
"""Build, sign, and publish the generated current Archive V3 release."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from archive_v3_release_tag import (
    ReleaseTagError,
    cargo_version,
    load_current_release_receipt,
    read_remote_refs,
    require_next_tag,
)


ROOT = Path(__file__).resolve().parents[1]


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
        [
            "git",
            "--no-replace-objects",
            "rev-parse",
            "--verify",
            f"refs/tags/{tag}^{{tag}}",
        ],
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


def checked_tag(*, allow_existing: bool) -> str:
    _, receipt = load_current_release_receipt(ROOT)
    require_next_tag(
        receipt.name,
        cargo_version(ROOT),
        read_remote_refs("origin"),
        allow_existing=allow_existing,
    )
    return receipt.name


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
    subparsers.add_parser("tag", help="print the exact next source-bound tag")

    pipeline = subparsers.add_parser("pipeline", help="run a tag-derived image stage")
    pipeline.add_argument("stage", choices=("preflight", "verify", "build", "push"))
    pipeline.add_argument("--config", type=Path, required=True)
    pipeline.add_argument("--output-dir", type=Path)
    pipeline.add_argument("--apply", action="store_true")
    pipeline.add_argument("--resume", action="store_true")
    pipeline.add_argument(
        "--tag-signing-key",
        type=Path,
        help="SSH public-key path used to create an absent signed release tag",
    )

    release = subparsers.add_parser(
        "release", help="build, push, sign, and publish the current release"
    )
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
        "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256": (
            arguments.evidence_public_key_sha256
        ),
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
