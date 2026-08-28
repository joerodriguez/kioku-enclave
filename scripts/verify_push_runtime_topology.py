#!/usr/bin/env python3
"""Fail closed unless maintenance rollout uses independently reviewed source."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import sys


SEAL_DOMAIN = b"kioku-push-terraform-root-source-seal-v1\0"
REVIEWED_ROLL_SCRIPT = "scripts/local-operations.sh"


@dataclass(frozen=True)
class DeploymentSourceSeal:
    head: str
    inventory: tuple[str, ...]
    digest: str

    def token(self) -> str:
        return f"push-runtime-source-seal-v1:{self.head}:{self.digest}"


# This is intentionally an exact reviewed-source pin, not a Terraform parser
# and not a seal derived from a mutable local remote-tracking ref. Changing any
# deployment source requires a separate enclave review that updates the commit,
# canonical Terraform root-source inventory, and digest together.
REVIEWED_DEPLOYMENT = DeploymentSourceSeal(
    head="0580e974fd6aa780f44f208e8f7ad6fd765d0fe4",
    inventory=(
        "infra/backend.tf",
        "infra/billing.tf",
        "infra/cicd.tf",
        "infra/enclave.tf",
        "infra/main.tf",
        "infra/monitoring.tf",
        "infra/outputs.tf",
        "infra/secrets.tf",
        "infra/variables.tf",
        "infra/voice_evaluation.tf",
    ),
    digest="8e12937f582abe272e51f8f1d093d41ada431d5d636792123c1fab1baabab4d5",
)


def git_output(repository: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=environment,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "git command failed"
        raise ValueError(detail)
    return result.stdout.strip()


def canonical_repository_path(deployment_repo: Path) -> Path:
    supplied = Path(os.path.abspath(os.fspath(deployment_repo)))
    if any(ord(character) < 32 or ord(character) == 127 for character in str(supplied)):
        raise ValueError("deployment repository path contains a control character")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as error:
        raise ValueError("deployment repository path does not resolve") from error
    if supplied != resolved:
        raise ValueError("deployment repository path contains a symlink component")
    if not resolved.is_dir():
        raise ValueError("deployment repository must be a directory")
    return resolved


def root_source_inventory(infra: Path) -> tuple[str, ...]:
    inventory: list[str] = []
    for path in infra.iterdir():
        if not (path.name.endswith(".tf") or path.name.endswith(".tf.json")):
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise ValueError(
                f"deployment root source is not a regular file: infra/{path.name}"
            )
        inventory.append(f"infra/{path.name}")
    return tuple(sorted(inventory, key=lambda value: value.encode("utf-8")))


def canonical_source_digest(repository: Path, inventory: tuple[str, ...]) -> str:
    digest = sha256()
    digest.update(SEAL_DOMAIN)
    for relative in inventory:
        path_bytes = relative.encode("utf-8")
        contents = (repository / relative).read_bytes()
        digest.update(len(path_bytes).to_bytes(8, "big"))
        digest.update(path_bytes)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return digest.hexdigest()


def repository_state(repository: Path) -> tuple[str, str]:
    head = git_output(repository, "rev-parse", "--verify", "HEAD^{commit}")
    dirty = git_output(
        repository,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    )
    return head, dirty


def verify_roll_script(repository: Path, relative: str, expected_head: str) -> Path:
    if not relative or any(
        ord(character) < 32 or ord(character) == 127 for character in relative
    ):
        raise ValueError("roll script path is empty or contains a control character")
    path = PurePosixPath(relative)
    if path.is_absolute() or relative != path.as_posix() or ".." in path.parts:
        raise ValueError("roll script must be a normalized relative path without '..'")

    candidate = repository.joinpath(*path.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise ValueError("roll script does not resolve") from error
    if candidate != resolved:
        raise ValueError("roll script path contains a symlink component")
    try:
        resolved.relative_to(repository)
    except ValueError as error:
        raise ValueError("roll script escapes the deployment repository") from error

    mode = resolved.lstat().st_mode
    if not stat.S_ISREG(mode) or not os.access(resolved, os.X_OK):
        raise ValueError("roll script must be a regular executable file")

    try:
        entry = git_output(repository, "ls-tree", expected_head, "--", relative)
    except ValueError as error:
        raise ValueError("roll script is not tracked at the reviewed commit") from error
    try:
        metadata, tracked_path = entry.split("\t", 1)
        tracked_mode, kind, expected_blob = metadata.split(" ", 2)
    except ValueError as error:
        raise ValueError("roll script is not tracked at the reviewed commit") from error
    if tracked_path != relative or tracked_mode != "100755" or kind != "blob":
        raise ValueError("roll script is not an executable blob at the reviewed commit")
    actual_blob = git_output(
        repository, "hash-object", "--no-filters", "--", relative
    )
    if actual_blob != expected_blob:
        raise ValueError("roll script bytes differ from the reviewed Git blob")
    return resolved


def verify(
    deployment_repo: Path,
    expected: DeploymentSourceSeal = REVIEWED_DEPLOYMENT,
) -> str:
    repository = canonical_repository_path(deployment_repo)
    infra = repository / "infra"
    if infra.is_symlink() or not infra.is_dir():
        raise ValueError("deployment repository lacks a regular infra/ directory")

    top_level = Path(git_output(repository, "rev-parse", "--show-toplevel"))
    if top_level.resolve() != repository.resolve():
        raise ValueError("deployment path must name the Git checkout root")
    if git_output(
        repository, "for-each-ref", "--format=%(refname)", "refs/replace"
    ):
        raise ValueError("deployment checkout contains Git replacement objects")

    head_before, dirty_before = repository_state(repository)
    if head_before != expected.head:
        raise ValueError(
            f"deployment HEAD is not the reviewed commit {expected.head}"
        )
    if dirty_before:
        raise ValueError("deployment checkout is not clean")

    inventory = root_source_inventory(infra)
    if inventory != expected.inventory:
        raise ValueError("deployment Terraform root-source inventory is not reviewed")
    digest = canonical_source_digest(repository, inventory)
    if digest != expected.digest:
        raise ValueError("deployment Terraform root-source digest is not reviewed")
    verify_roll_script(repository, REVIEWED_ROLL_SCRIPT, expected.head)

    # Recheck around the file reads so a concurrent checkout mutation cannot
    # produce a token from mixed repository states.
    head_after, dirty_after = repository_state(repository)
    if head_after != head_before or dirty_after:
        raise ValueError("deployment checkout changed during source verification")
    if root_source_inventory(infra) != inventory:
        raise ValueError("deployment source inventory changed during verification")
    if canonical_source_digest(repository, inventory) != digest:
        raise ValueError("deployment source bytes changed during verification")
    return expected.token()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--canonical-path", action="store_true")
    parser.add_argument("deployment_repo", type=Path)
    args = parser.parse_args()
    try:
        if args.canonical_path:
            token = str(canonical_repository_path(args.deployment_repo))
        else:
            token = verify(args.deployment_repo)
    except (OSError, UnicodeError, ValueError) as error:
        print(f"maintenance rollout source-seal refusal: {error}", file=sys.stderr)
        return 1
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
