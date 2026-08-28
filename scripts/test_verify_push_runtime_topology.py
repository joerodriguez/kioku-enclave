#!/usr/bin/env python3
"""Hermetic adversarial tests for the maintenance rollout source seal."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import subprocess
import tempfile
import unittest

from verify_push_runtime_topology import (
    DeploymentSourceSeal,
    REVIEWED_DEPLOYMENT,
    canonical_repository_path,
    canonical_source_digest,
    root_source_inventory,
    verify,
    verify_roll_script,
)


VALID = """
resource "google_compute_region_instance_group_manager" "kioku_enclave" {
  name               = "kioku-enclave"
  base_instance_name = "kioku-enclave"
  target_size        = 2
  version { instance_template = google_compute_instance_template.enclave.id }
}
"""


class PushRuntimeSourceSealTests(unittest.TestCase):
    def run_git(self, root: Path, *arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    def commit(self, root: Path, message: str) -> None:
        self.run_git(root, "add", "-A")
        self.run_git(root, "commit", "-q", "-m", message)

    def fixture(self) -> tuple[Path, DeploymentSourceSeal]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        (root / "infra").mkdir()
        (root / "scripts").mkdir()
        (root / "infra" / "enclave.tf").write_text(VALID, encoding="utf-8")
        roll_script = root / "scripts" / "local-operations.sh"
        roll_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        roll_script.chmod(0o755)
        (root / "README.md").write_text("deployment fixture\n", encoding="utf-8")
        self.run_git(root, "init", "-q")
        self.run_git(root, "config", "user.name", "Topology Test")
        self.run_git(root, "config", "user.email", "topology@example.invalid")
        self.commit(root, "fixture")
        inventory = root_source_inventory(root / "infra")
        seal = DeploymentSourceSeal(
            head=self.run_git(root, "rev-parse", "HEAD"),
            inventory=inventory,
            digest=canonical_source_digest(root, inventory),
        )
        return root, seal

    def assert_refused(
        self, root: Path, seal: DeploymentSourceSeal, pattern: str
    ) -> None:
        with self.assertRaisesRegex(ValueError, pattern):
            verify(root, seal)

    def test_exact_clean_commit_inventory_and_digest_are_accepted(self) -> None:
        root, seal = self.fixture()
        self.assertEqual(verify(root, seal), seal.token())

    def test_default_seal_is_compiled_reviewed_source_not_local_origin_main(self) -> None:
        root, seal = self.fixture()
        self.run_git(root, "update-ref", "refs/remotes/origin/main", seal.head)
        with self.assertRaisesRegex(ValueError, "reviewed commit"):
            verify(root)
        self.assertEqual(
            REVIEWED_DEPLOYMENT,
            DeploymentSourceSeal(
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
            ),
        )

    def test_symlinked_leaf_and_ancestor_paths_are_refused_before_verification(
        self,
    ) -> None:
        root, _ = self.fixture()
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        aliases = Path(temporary.name).resolve()

        leaf = aliases / "deployment"
        leaf.symlink_to(root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink component"):
            canonical_repository_path(leaf)

        ancestor = aliases / "parent"
        ancestor.symlink_to(root.parent, target_is_directory=True)
        supplied = ancestor / root.name
        with self.assertRaisesRegex(ValueError, "symlink component"):
            canonical_repository_path(supplied)
        ancestor.unlink()
        ancestor.symlink_to(aliases, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "does not resolve|symlink component"):
            canonical_repository_path(supplied)

    def test_roll_script_parent_and_absolute_escapes_are_refused(self) -> None:
        root, seal = self.fixture()
        with self.assertRaisesRegex(ValueError, "normalized relative path"):
            verify_roll_script(root, "../outside.sh", seal.head)
        with self.assertRaisesRegex(ValueError, "normalized relative path"):
            verify_roll_script(
                root, str(root / "scripts/local-operations.sh"), seal.head
            )

    def test_internal_symlink_roll_script_is_refused(self) -> None:
        root, seal = self.fixture()
        link = root / "scripts" / "local-operations.sh"
        link.unlink()
        real = root / "scripts" / "real-roll.sh"
        real.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        real.chmod(0o755)
        link.symlink_to(real)
        self.commit(root, "tracked roll symlink")
        current = replace(seal, head=self.run_git(root, "rev-parse", "HEAD"))
        with self.assertRaisesRegex(ValueError, "symlink component"):
            verify(root, current)

    def test_roll_script_mutation_cannot_hide_behind_assume_unchanged(self) -> None:
        root, seal = self.fixture()
        relative = "scripts/local-operations.sh"
        early = verify(root, seal)
        self.assertEqual(early, seal.token())
        self.run_git(root, "update-index", "--assume-unchanged", relative)
        script = root / relative
        script.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "bytes differ"):
            verify(root, seal)

    def test_committed_source_mutation_cannot_replace_sealed_source(self) -> None:
        root, seal = self.fixture()
        spoof = VALID.replace(
            "target_size        = 2",
            "target_size        = 3",
        )
        (root / "infra" / "enclave.tf").write_text(spoof, encoding="utf-8")
        self.commit(root, "change fleet size")
        self.assert_refused(root, seal, "reviewed commit")

    def test_resource_kind_mutation_cannot_replace_sealed_source(self) -> None:
        root, seal = self.fixture()
        source = VALID.replace(
            'resource "google_compute_region_instance_group_manager" "kioku_enclave"',
            'resource "google_compute_instance_template" "kioku_enclave"',
        )
        (root / "infra" / "enclave.tf").write_text(source, encoding="utf-8")
        self.commit(root, "change resource kind")
        self.assert_refused(root, seal, "reviewed commit")

    def test_module_path_outside_infra_cannot_extend_reviewed_source(self) -> None:
        root, seal = self.fixture()
        (root / "infra" / "enclave.tf").write_text(
            VALID + '\nmodule "overlap" { source = "../overlap" }\n',
            encoding="utf-8",
        )
        (root / "overlap").mkdir()
        (root / "overlap" / "main.tf").write_text(
            'resource "google_compute_instance_template" "overlap" {}\n', encoding="utf-8"
        )
        self.commit(root, "outside module")
        self.assert_refused(root, seal, "reviewed commit")

    def test_extra_tf_json_is_not_hidden_from_exact_inventory(self) -> None:
        root, seal = self.fixture()
        (root / "infra" / "extra.tf.json").write_text("{}\n", encoding="utf-8")
        self.commit(root, "extra root source")
        current_head = self.run_git(root, "rev-parse", "HEAD")
        self.assert_refused(root, replace(seal, head=current_head), "inventory")

    def test_source_symlink_is_refused(self) -> None:
        root, seal = self.fixture()
        enclave = root / "infra" / "enclave.tf"
        enclave.unlink()
        enclave.symlink_to(root / "README.md")
        self.commit(root, "source symlink")
        current_head = self.run_git(root, "rev-parse", "HEAD")
        self.assert_refused(
            root, replace(seal, head=current_head), "not a regular file"
        )

    def test_dirty_wrong_head_and_wrong_digest_are_refused(self) -> None:
        root, seal = self.fixture()
        (root / "README.md").write_text("dirty\n", encoding="utf-8")
        self.assert_refused(root, seal, "not clean")

        self.run_git(root, "checkout", "--", "README.md")
        self.assert_refused(root, replace(seal, head="0" * 40), "reviewed commit")
        self.assert_refused(
            root, replace(seal, digest="0" * 64), "digest is not reviewed"
        )

    def test_mutation_between_early_check_and_roll_is_refused(self) -> None:
        root, seal = self.fixture()
        early = verify(root, seal)
        self.assertEqual(early, seal.token())
        (root / "infra" / "enclave.tf").write_text(
            VALID + "\n# changed after early preflight\n", encoding="utf-8"
        )
        self.assert_refused(root, seal, "not clean")

    def test_git_replacement_ref_is_refused_before_identity_adoption(self) -> None:
        root, seal = self.fixture()
        (root / "README.md").write_text("second commit\n", encoding="utf-8")
        self.commit(root, "second fixture commit")
        current = self.run_git(root, "rev-parse", "HEAD")
        self.run_git(root, "replace", current, seal.head)
        with self.assertRaisesRegex(ValueError, "replacement objects"):
            verify(root, replace(seal, head=current))


if __name__ == "__main__":
    unittest.main()
