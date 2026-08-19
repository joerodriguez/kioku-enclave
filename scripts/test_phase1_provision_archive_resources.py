#!/usr/bin/env python3
"""Invariant contracts for the emitted ADR-0022 Phase-1 provisioning plan."""

from __future__ import annotations

import contextlib
import hashlib
import io
from pathlib import Path
import re
import shlex
import tempfile
import unittest

import phase1_provision_archive_resources as tool

REPO_ROOT = Path(__file__).resolve().parents[1]

SAMPLE = {
    "--decision-archive-project": "kioku-joerodriguez",
    "--decision-archive-project-number": "123456789012",
    "--decision-witness-project": "kioku-joerodriguez",
    "--decision-witness-project-number": "123456789012",
    "--decision-witness-database": "archive-v3-witness",
    "--decision-archive-bucket": "kioku-archive-v3-prod",
    "--decision-backups-bucket": "kioku-archive-v3-backups",
    "--decision-image-digest": "sha256:" + "ab" * 32,
    "--decision-kms-location": "us-central1",
    "--decision-kms-key-ring": "kioku",
    "--decision-kms-key": "kioku-kek",
    "--decision-registry-kms-version": "2",
}

FIRESTORE_SERVICE_AGENT = (
    "serviceAccount:service-123456789012@gcp-sa-firestore.iam.gserviceaccount.com"
)

# Substring bans checked against every emitted command. "admin" (case-folded)
# also catches objectAdmin/Admin roles; predefined broad roles are banned
# outright because every grant in this plan must be a custom role.
BANNED_COMMAND_SUBSTRINGS = (
    "admin",
    "storage.objects.list",
    "storage.objects.delete",
    "storage.objects.update",
    "setiampolicy",
    "roles/owner",
    "roles/editor",
    "roles/storage.",
    "roles/datastore.",
    "roles/cloudkms.",
    "roles/firebase",
)


def flag_args(
    overrides: dict[str, str] | None = None, drop: tuple[str, ...] = ()
) -> list[str]:
    values = dict(SAMPLE)
    if overrides:
        values.update(overrides)
    for key in drop:
        values.pop(key)
    argv: list[str] = []
    for key, value in values.items():
        argv.extend([key, value])
    return argv


def rust_constant(source: Path, name: str) -> str:
    match = re.search(name + r':\s*&str\s*=\s*"([^"]+)"', source.read_text(), re.S)
    assert match is not None, f"{name} not found in {source}"
    return match.group(1)


class Phase1ProvisioningPlanTests(unittest.TestCase):
    def run_main(self, argv: list[str]) -> tuple[object, str, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                code: object = tool.main(argv)
            except SystemExit as error:
                code = error.code
        return code, stdout.getvalue(), stderr.getvalue()

    def decisions(self) -> tool.Decisions:
        return tool.validate_decisions(
            {
                flag: SAMPLE["--" + flag.replace("_", "-")]
                for flag, _, _ in tool.DECISION_FLAGS
            }
        )

    def commands(self) -> list[str]:
        return [step.command for step in tool.build_plan(self.decisions())]

    def test_every_iam_member_is_digest_principalset_or_backup_service_agent(
        self,
    ) -> None:
        members = []
        for command in self.commands():
            argv = shlex.split(command)
            for index, token in enumerate(argv):
                if token == "--member":
                    members.append(argv[index + 1])
        self.assertEqual(len(members), 3, members)
        principal_sets = [m for m in members if m.startswith("principalSet://")]
        self.assertEqual(len(principal_sets), 2, members)
        for member in principal_sets:
            self.assertTrue(
                member.startswith("principalSet://iam.googleapis.com/projects/"),
                member,
            )
            self.assertIn(
                "/attribute.image_digest/" + SAMPLE["--decision-image-digest"], member
            )
        remaining = [m for m in members if not m.startswith("principalSet://")]
        self.assertEqual(remaining, [FIRESTORE_SERVICE_AGENT])

    def test_no_banned_role_or_permission_substrings_in_commands(self) -> None:
        for command in self.commands():
            lowered = command.lower()
            for banned in BANNED_COMMAND_SUBSTRINGS:
                self.assertNotIn(banned, lowered, command)
        for command in self.commands():
            argv = shlex.split(command)
            for index, token in enumerate(argv):
                if token == "--role":
                    self.assertTrue(
                        argv[index + 1].startswith("projects/"),
                        f"non-custom role granted: {command}",
                    )

    def test_witness_database_is_named_and_never_default(self) -> None:
        commands = self.commands()
        self.assertTrue(
            any(
                "firestore databases create" in command
                and "--database archive-v3-witness" in command
                for command in commands
            ),
            commands,
        )
        for command in commands:
            self.assertNotIn("(default)", command)
        code, _, stderr = self.run_main(
            flag_args({"--decision-witness-database": "(default)"})
        )
        self.assertNotEqual(code, 0)
        self.assertIn("REQUIRED_DECISION_WITNESS_DATABASE", stderr)
        self.assertIn("(default)", stderr)

    def test_archive_bucket_flags_and_forbidden_bucket_features(self) -> None:
        creates = [
            command
            for command in self.commands()
            if "buckets create" in command
        ]
        self.assertEqual(len(creates), 2, creates)
        for command in creates:
            self.assertIn("--uniform-bucket-level-access", command)
            self.assertIn("--public-access-prevention", command)
            self.assertIn("--location us-central1", command)
        expects = [step.expect for step in tool.build_plan(self.decisions())]
        self.assertTrue(
            any("public_access_prevention: enforced" in expect for expect in expects)
        )
        self.assertTrue(
            any(
                "buckets update gs://kioku-archive-v3-prod --versioning" in command
                for command in self.commands()
            )
        )
        for command in self.commands():
            lowered = command.lower()
            self.assertNotIn("lifecycle", lowered, command)
            self.assertNotIn("retention", lowered, command)

    def test_missing_decision_flags_exit_nonzero_naming_them(self) -> None:
        code, _, stderr = self.run_main([])
        self.assertEqual(code, 2)
        for _, placeholder, _ in tool.DECISION_FLAGS:
            self.assertIn(placeholder, stderr)
        code, _, stderr = self.run_main(
            flag_args(drop=("--decision-witness-project",))
        )
        self.assertEqual(code, 2)
        self.assertIn("REQUIRED_DECISION_WITNESS_PROJECT", stderr)
        self.assertNotIn("REQUIRED_DECISION_ARCHIVE_BUCKET", stderr)

    def test_placeholder_literal_values_are_refused(self) -> None:
        code, _, stderr = self.run_main(
            flag_args(
                {"--decision-witness-project": "REQUIRED_DECISION_WITNESS_PROJECT"}
            )
        )
        self.assertEqual(code, 2)
        self.assertIn("refuses to fill", stderr)

    def test_invalid_decision_grammar_is_rejected(self) -> None:
        for overrides, placeholder in (
            (
                {"--decision-archive-project-number": "0123"},
                "REQUIRED_DECISION_ARCHIVE_PROJECT_NUMBER",
            ),
            (
                {"--decision-image-digest": "sha256:short"},
                "REQUIRED_DECISION_IMAGE_DIGEST",
            ),
            (
                {"--decision-registry-kms-version": "01"},
                "REQUIRED_DECISION_REGISTRY_KMS_VERSION",
            ),
            (
                {"--decision-backups-bucket": SAMPLE["--decision-archive-bucket"]},
                "REQUIRED_DECISION_BACKUPS_BUCKET",
            ),
        ):
            code, _, stderr = self.run_main(flag_args(overrides))
            self.assertEqual(code, 2, overrides)
            self.assertIn(placeholder, stderr)

    def test_plan_digest_is_stable_and_flag_sensitive(self) -> None:
        first = self.run_main(flag_args() + ["--plan-digest"])
        second = self.run_main(flag_args() + ["--plan-digest"])
        self.assertEqual(first, second)
        code, stdout, _ = first
        self.assertEqual(code, 0)
        self.assertRegex(stdout.strip(), r"\Asha256:[0-9a-f]{64}\Z")
        expected = "sha256:" + hashlib.sha256(
            tool.canonical_plan_text(self.decisions()).encode("utf-8")
        ).hexdigest()
        self.assertEqual(stdout.strip(), expected)
        for overrides in (
            {"--decision-archive-bucket": "kioku-archive-v3-prod-2"},
            {"--decision-image-digest": "sha256:" + "cd" * 32},
            {"--decision-registry-kms-version": "3"},
        ):
            _, changed, _ = self.run_main(flag_args(overrides) + ["--plan-digest"])
            self.assertNotEqual(changed, stdout, overrides)

    def test_wif_audiences_match_pinned_source_constants(self) -> None:
        gcs_source = REPO_ROOT / "src" / "archive_v3_gcs_auth.rs"
        witness_source = REPO_ROOT / "src" / "archive_v3_firestore_witness.rs"
        number = SAMPLE["--decision-archive-project-number"]
        gcs_audience = (
            rust_constant(gcs_source, "ARCHIVE_GCS_WIF_AUDIENCE_PREFIX")
            + number
            + rust_constant(gcs_source, "ARCHIVE_GCS_WIF_AUDIENCE_SUFFIX")
        )
        witness_audience = (
            rust_constant(witness_source, "ARCHIVE_WITNESS_WIF_AUDIENCE_PREFIX")
            + number
            + rust_constant(witness_source, "ARCHIVE_WITNESS_WIF_AUDIENCE_SUFFIX")
        )
        self.assertEqual(tool.archive_gcs_audience(number), gcs_audience)
        self.assertEqual(tool.archive_witness_audience(number), witness_audience)
        commands = self.commands()
        self.assertTrue(
            any(
                "providers create-oidc archive-gcs " in command
                and shlex.quote(gcs_audience) in command
                for command in commands
            ),
            commands,
        )
        self.assertTrue(
            any(
                "providers create-oidc archive-witness " in command
                and shlex.quote(witness_audience) in command
                for command in commands
            ),
            commands,
        )

    def test_emit_shell_writes_fail_closed_reviewable_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "phase1.sh"
            code, _, _ = self.run_main(flag_args() + ["--emit-shell", str(path)])
            self.assertEqual(code, 0)
            content = path.read_text(encoding="utf-8")
        self.assertTrue(content.startswith("#!/usr/bin/env bash"))
        self.assertIn("set -euo pipefail", content)
        digest = "sha256:" + hashlib.sha256(
            tool.canonical_plan_text(self.decisions()).encode("utf-8")
        ).hexdigest()
        self.assertIn(f'"${{{tool.APPROVAL_ENV}:-}}" != "{digest}"', content)
        lines = content.splitlines()
        for step in tool.build_plan(self.decisions()):
            self.assertIn(f"# justification: {step.justification}", lines)
            self.assertIn(step.command, lines)
            # Identical commands can legitimately repeat (same-project
            # decisions), so require the command within the lines directly
            # after its own justification comment.
            justification_index = lines.index(f"# justification: {step.justification}")
            self.assertIn(
                step.command,
                lines[justification_index + 1 : justification_index + 3],
                step.title,
            )

    def test_no_kms_mutation_and_no_new_kms_iam(self) -> None:
        for command in self.commands():
            if " kms " not in command:
                continue
            self.assertTrue(
                "describe" in command or "get-iam-policy" in command,
                f"non-read-only KMS command emitted: {command}",
            )
        joined = "\n".join(self.commands())
        self.assertNotIn("kms keys create", joined)
        self.assertNotIn("kms keyrings create", joined)
        self.assertNotIn("kms keys versions create", joined)
        self.assertNotIn("kms keys add-iam-policy-binding", joined)

    def test_custom_role_permission_sets_are_exact(self) -> None:
        roles: dict[str, str] = {}
        for command in self.commands():
            if "iam roles create" not in command:
                continue
            argv = shlex.split(command)
            role_id = argv[argv.index("create") + 1]
            roles[role_id] = argv[argv.index("--permissions") + 1]
        self.assertEqual(
            roles,
            {
                "kiokuArchiveV3ObjectWriter": (
                    "storage.objects.create,storage.objects.get"
                ),
                "kiokuArchiveV3WitnessWriter": (
                    "datastore.databases.get,datastore.entities.create,"
                    "datastore.entities.get,datastore.entities.update"
                ),
                "kiokuArchiveV3BackupExportWriter": (
                    "storage.buckets.get,storage.objects.create,storage.objects.get"
                ),
            },
        )

    def test_conditional_witness_binding_scopes_the_exact_database(self) -> None:
        bindings = [
            command
            for command in self.commands()
            if "projects add-iam-policy-binding" in command
        ]
        self.assertEqual(len(bindings), 1, bindings)
        binding = bindings[0]
        database_resource = "projects/kioku-joerodriguez/databases/archive-v3-witness"
        self.assertIn(f'resource.name == "{database_resource}"', binding)
        self.assertIn(
            f'resource.name.startsWith("{database_resource}/")', binding
        )
        self.assertIn("workloadIdentityPools/archive-witness-attest", binding)

    def test_default_mode_prints_the_canonical_plan(self) -> None:
        code, stdout, stderr = self.run_main(flag_args())
        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertEqual(stdout, tool.canonical_plan_text(self.decisions()))
        self.assertIn("grants no permission", stdout)
        for _, placeholder, _ in tool.DECISION_FLAGS:
            self.assertIn(placeholder, stdout)
        self.assertIn("deliberate omissions", stdout)

    def test_read_only_and_mutating_steps_are_honestly_labeled(self) -> None:
        for step in tool.build_plan(self.decisions()):
            read_only_marker = (
                "describe" in step.command
                or "get-value" in step.command
                or "get-iam-policy" in step.command
            )
            self.assertEqual(
                not step.mutating,
                read_only_marker,
                f"{step.title}: {step.command}",
            )


if __name__ == "__main__":
    unittest.main()
