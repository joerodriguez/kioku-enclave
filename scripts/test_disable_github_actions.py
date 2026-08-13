#!/usr/bin/env python3
"""Contracts for the one-time hosted-Actions cutover."""

from __future__ import annotations

import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("disable_github_actions.py")


def load_module():
    specification = importlib.util.spec_from_file_location("disable_github_actions", SCRIPT)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class DisableActionsTests(unittest.TestCase):
    def test_audit_is_read_only(self) -> None:
        module = load_module()
        calls: list[tuple[list[str], str]] = []

        def fake_api(arguments, *, method="GET", fields=None):
            calls.append((arguments, method))
            if arguments[0].endswith("/rulesets"):
                return []
            return {"enabled": True}

        def fake_run(command, **_kwargs):
            if command[-1].endswith("/rulesets"):
                return SimpleNamespace(returncode=0, stdout="[]", stderr="")
            return SimpleNamespace(
                returncode=0,
                stdout='{"contexts":["CI"],"checks":[]}',
                stderr="",
            )

        with patch.object(module, "gh_json", side_effect=fake_api), patch.object(
            module.subprocess, "run", side_effect=fake_run
        ), patch.object(sys, "argv", [str(SCRIPT)]), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(module.main(), 0)
        self.assertTrue(calls)
        self.assertTrue(all(method == "GET" for _, method in calls))

    def test_apply_requires_exact_confirmation_before_mutation(self) -> None:
        module = load_module()
        with patch.object(module, "actions_enabled", return_value=True), patch.object(
            module, "required_status_checks", return_value=["CI"]
        ), patch.object(
            module, "required_ruleset_status_checks", return_value=[]
        ), patch.object(module, "disable_actions") as disable, patch.object(
            sys, "argv", [str(SCRIPT), "--apply"]
        ), patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(module.main(), 1)
        disable.assert_not_called()

    def test_unreadable_branch_protection_fails_closed(self) -> None:
        module = load_module()
        completed = SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="gh: Resource not accessible by integration (HTTP 403)",
        )
        with patch.object(module.subprocess, "run", return_value=completed):
            with self.assertRaises(module.CutoverError):
                module.required_status_checks("owner/repository")

    def test_private_plan_limit_requires_verified_admin(self) -> None:
        module = load_module()
        completed = SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=f"gh: {module.FEATURE_UNAVAILABLE} (HTTP 403)",
        )
        repository = {
            "visibility": "private",
            "permissions": {"admin": True},
        }
        with patch.object(module.subprocess, "run", return_value=completed), patch.object(
            module, "gh_json", return_value=repository
        ):
            self.assertEqual(module.required_status_checks("owner/repository"), [])
            self.assertEqual(module.required_ruleset_status_checks("owner/repository"), [])

    def test_private_plan_limit_without_admin_fails_closed(self) -> None:
        module = load_module()
        completed = SimpleNamespace(
            returncode=1,
            stdout="",
            stderr=f"gh: {module.FEATURE_UNAVAILABLE} (HTTP 403)",
        )
        repository = {
            "visibility": "private",
            "permissions": {"admin": False},
        }
        with patch.object(module.subprocess, "run", return_value=completed), patch.object(
            module, "gh_json", return_value=repository
        ):
            with self.assertRaises(module.CutoverError):
                module.required_status_checks("owner/repository")
            with self.assertRaises(module.CutoverError):
                module.required_ruleset_status_checks("owner/repository")

    def test_apply_removes_checks_before_disabling_actions(self) -> None:
        module = load_module()
        enabled = {repository: True for repository in module.REPOSITORIES}
        checks = {repository: ["CI"] for repository in module.REPOSITORIES}
        events: list[str] = []

        def disable(repository):
            events.append(f"disable:{repository}")
            enabled[repository] = False

        def remove(repository):
            events.append(f"remove:{repository}")
            checks[repository] = []

        with patch.object(module, "actions_enabled", side_effect=lambda repo: enabled[repo]), patch.object(
            module, "required_status_checks", side_effect=lambda repo: checks[repo]
        ), patch.object(
            module, "required_ruleset_status_checks", return_value=[]
        ), patch.object(module, "disable_actions", side_effect=disable), patch.object(
            module, "remove_required_status_checks", side_effect=remove
        ), patch.object(
            sys, "argv", [str(SCRIPT), "--apply", "--confirm", "DISABLE-GITHUB-ACTIONS"]
        ), patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(module.main(), 0)
        first_disable = next(index for index, event in enumerate(events) if event.startswith("disable:"))
        last_remove = max(index for index, event in enumerate(events) if event.startswith("remove:"))
        self.assertLess(last_remove, first_disable)
        self.assertFalse(any(enabled.values()))

    def test_apply_refuses_ruleset_checks_before_mutation(self) -> None:
        module = load_module()
        with patch.object(module, "actions_enabled", return_value=True), patch.object(
            module, "required_status_checks", return_value=[]
        ), patch.object(
            module, "required_ruleset_status_checks", return_value=["CI"]
        ), patch.object(module, "disable_actions") as disable, patch.object(
            sys, "argv", [str(SCRIPT), "--apply", "--confirm", "DISABLE-GITHUB-ACTIONS"]
        ), patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(module.main(), 1)
        disable.assert_not_called()


if __name__ == "__main__":
    unittest.main()
