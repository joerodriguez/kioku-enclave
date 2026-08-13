#!/usr/bin/env python3
"""Fail-closed one-time GitHub Actions cutover for both Kioku repositories.

The default command only audits state. ``--apply`` first removes and verifies
any branch-protection status-check gate that would otherwise wait forever for a
deleted workflow, then disables Actions in both repositories. GitHub remains
available for pull requests, signed tags, and immutable release hosting.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any


REPOSITORIES = ("joerodriguez/kioku-enclave", "joerodriguez/kioku")
FEATURE_UNAVAILABLE = "Upgrade to GitHub Pro or make this repository public to enable this feature."


class CutoverError(RuntimeError):
    pass


def gh_json(arguments: list[str], *, method: str = "GET", fields: dict[str, str] | None = None) -> Any:
    command = ["gh", "api", *arguments]
    if method != "GET":
        command.extend(["--method", method])
    for name, value in (fields or {}).items():
        # --field performs typed conversion (notably false -> JSON boolean),
        # whereas --raw-field would send the string "false" and be rejected.
        command.extend(["--field", f"{name}={value}"])
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    if result.returncode:
        raise CutoverError("GitHub rejected the repository administration request")
    if not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CutoverError("GitHub returned malformed administration state") from error


def actions_enabled(repository: str) -> bool:
    payload = gh_json([f"repos/{repository}/actions/permissions"])
    if not isinstance(payload, dict) or type(payload.get("enabled")) is not bool:
        raise CutoverError("GitHub Actions permission state is malformed")
    return payload["enabled"]


def unavailable_for_private_admin(repository: str, stderr: str) -> bool:
    """Recognize GitHub's exact plan-limit response without accepting generic 403s."""
    if FEATURE_UNAVAILABLE not in stderr or not re.search(r"\bHTTP 403\b", stderr):
        return False
    payload = gh_json([f"repos/{repository}"])
    if not isinstance(payload, dict):
        raise CutoverError("GitHub repository permission state is malformed")
    permissions = payload.get("permissions")
    if not isinstance(permissions, dict) or type(permissions.get("admin")) is not bool:
        raise CutoverError("GitHub repository permission state is malformed")
    return payload.get("visibility") == "private" and permissions["admin"] is True


def required_status_checks(repository: str) -> list[str]:
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/branches/main/protection/required_status_checks"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        if "Branch not protected" in result.stderr or re.search(
            r"\bHTTP 404\b", result.stderr
        ):
            return []
        if unavailable_for_private_admin(repository, result.stderr):
            return []
        raise CutoverError(
            "could not read branch-protection status checks; repository-admin permission is required"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CutoverError("GitHub branch-protection state is malformed") from error
    contexts = payload.get("contexts")
    checks = payload.get("checks", [])
    if not isinstance(contexts, list) or not all(isinstance(item, str) for item in contexts):
        raise CutoverError("GitHub branch-protection contexts are malformed")
    if not isinstance(checks, list):
        raise CutoverError("GitHub branch-protection checks are malformed")
    names = list(contexts)
    for item in checks:
        if not isinstance(item, dict) or not isinstance(item.get("context"), str):
            raise CutoverError("GitHub branch-protection checks are malformed")
        names.append(item["context"])
    return sorted(set(names))


def required_ruleset_status_checks(repository: str) -> list[str]:
    result = subprocess.run(
        ["gh", "api", f"repos/{repository}/rulesets"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        if unavailable_for_private_admin(repository, result.stderr):
            return []
        raise CutoverError("could not read GitHub repository rulesets")
    try:
        summaries = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise CutoverError("GitHub repository-ruleset state is malformed") from error
    if not isinstance(summaries, list):
        raise CutoverError("GitHub repository-ruleset state is malformed")
    names: list[str] = []
    for summary in summaries:
        if not isinstance(summary, dict) or not isinstance(summary.get("id"), int):
            raise CutoverError("GitHub repository-ruleset summary is malformed")
        details = gh_json([f"repos/{repository}/rulesets/{summary['id']}"])
        if not isinstance(details, dict):
            raise CutoverError("GitHub repository-ruleset detail is malformed")
        if details.get("enforcement") == "disabled":
            continue
        rules = details.get("rules")
        if not isinstance(rules, list):
            raise CutoverError("GitHub repository-ruleset rules are malformed")
        for rule in rules:
            if not isinstance(rule, dict):
                raise CutoverError("GitHub repository-ruleset rule is malformed")
            if rule.get("type") != "required_status_checks":
                continue
            checks = rule.get("parameters", {}).get("required_status_checks")
            if not isinstance(checks, list):
                raise CutoverError("GitHub ruleset status checks are malformed")
            for check in checks:
                if not isinstance(check, dict) or not isinstance(check.get("context"), str):
                    raise CutoverError("GitHub ruleset status check is malformed")
                names.append(check["context"])
    return sorted(set(names))


def disable_actions(repository: str) -> None:
    gh_json(
        [f"repos/{repository}/actions/permissions"],
        method="PUT",
        fields={"enabled": "false"},
    )


def remove_required_status_checks(repository: str) -> None:
    result = subprocess.run(
        [
            "gh",
            "api",
            f"repos/{repository}/branches/main/protection/required_status_checks",
            "--method",
            "DELETE",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode and "Branch not protected" not in result.stderr:
        raise CutoverError("could not remove stale required status checks")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="perform the one-time repository cutover")
    parser.add_argument(
        "--confirm",
        help="required with --apply: DISABLE-GITHUB-ACTIONS",
    )
    arguments = parser.parse_args()
    try:
        before = {
            repository: {
                "actions_enabled": actions_enabled(repository),
                "required_status_checks": required_status_checks(repository),
                "ruleset_status_checks": required_ruleset_status_checks(repository),
            }
            for repository in REPOSITORIES
        }
        if not arguments.apply:
            print(json.dumps(before, sort_keys=True, indent=2))
            print("audit only; no GitHub setting changed")
            return 0
        if arguments.confirm != "DISABLE-GITHUB-ACTIONS":
            raise CutoverError("--apply requires --confirm DISABLE-GITHUB-ACTIONS")
        ruleset_blockers = {
            repository: state["ruleset_status_checks"]
            for repository, state in before.items()
            if state["ruleset_status_checks"]
        }
        if ruleset_blockers:
            raise CutoverError(
                "remove hosted required-status-check rules from repository rulesets before cutover"
            )

        # Remove hosted-only merge gates first, then verify their absence. If
        # that administrative step fails, Actions remains enabled and the
        # repository stays in its recoverable pre-cutover state.
        for repository in REPOSITORIES:
            if before[repository]["required_status_checks"]:
                remove_required_status_checks(repository)
                if required_status_checks(repository):
                    raise CutoverError("required status checks remained after removal")

        for repository in REPOSITORIES:
            disable_actions(repository)
            if actions_enabled(repository):
                raise CutoverError("GitHub Actions remained enabled after the cutover request")

        after = {repository: actions_enabled(repository) for repository in REPOSITORIES}
        if any(after.values()):
            raise CutoverError("GitHub Actions cutover verification failed")
        print("GitHub Actions disabled in both Kioku repositories; hosted workflows can no longer run")
        return 0
    except CutoverError as error:
        print(f"Actions cutover refused: {error}.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
