#!/usr/bin/env python3
"""Static fail-closed contracts for immutable release publication."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "scripts" / "release.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
METADATA_VERIFIER = ROOT / "scripts" / "verify_release_metadata.py"


class ReleasePublicationRaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = RELEASE.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.metadata_verifier = METADATA_VERIFIER.read_text(encoding="utf-8")

    def test_ci_cannot_publish_a_release_for_a_generic_verified_signer(self) -> None:
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("Automatically publish GitHub Release", self.workflow)
        self.assertNotIn("gh release create", self.workflow)
        signer_check = self.source.index('grep -qxF "$RELEASE_SIGNER_FINGERPRINT"')
        signer_call = self.source.index("\n  verify_tag_signer\n")
        release_create = self.source.index('if gh release create "$RELEASE_TAG"')
        self.assertLess(signer_check, signer_call)
        self.assertLess(signer_call, release_create)

    def test_refreshes_state_after_build_evidence_and_before_mutation(self) -> None:
        evidence = self.source.index("Verifying signed GitHub build provenance")
        refresh = self.source.index("\nrefresh_release_state_before_mutation\nif ", evidence)
        create = self.source.index("\n  create_release_or_reverify_publication_race\n", refresh)
        draft_edit = self.source.index('gh release edit "$RELEASE_TAG"', refresh)
        self.assertGreater(refresh, evidence)
        self.assertLess(refresh, create)
        self.assertLess(refresh, draft_edit)

    def test_failed_create_rechecks_and_reverifies_the_exact_release(self) -> None:
        start = self.source.index("create_release_or_reverify_publication_race() {")
        end = self.source.index("refresh_release_state_before_mutation\nif ", start)
        fallback = self.source[start:end]
        self.assertIn('if gh release create "$RELEASE_TAG"', fallback)
        self.assertIn("refresh_release_state_before_mutation", fallback)
        self.assertIn('"$RELEASE_EXISTS" == "true"', fallback)
        self.assertIn('"$RELEASE_IS_DRAFT" == "false"', fallback)
        self.assertIn("reverify_published_immutable_release", fallback)
        self.assertIn("failed without an exact published immutable release", fallback)

    def test_race_acceptance_requires_complete_immutable_public_release(self) -> None:
        start = self.source.index("reverify_published_immutable_release() {")
        end = self.source.index("refresh_release_state_before_mutation\nif ", start)
        verifier = self.source[start:end]
        self.assertIn('"$RELEASE_IS_DRAFT" != "false"', verifier)
        self.assertIn('"$RELEASE_IS_IMMUTABLE" != "true"', verifier)
        self.assertIn('"$RELEASE_IS_PRERELEASE" != "$EXPECTED_PRERELEASE"', verifier)
        self.assertIn('"$RELEASE_ASSETS_CSV" != "$EXPECTED_ASSETS_CSV"', verifier)
        self.assertIn('cmp -s "$WORK_DIR/$asset_name"', verifier)

    def test_hostile_or_malformed_release_state_fails_closed(self) -> None:
        start = self.source.index("refresh_release_state_before_mutation() {")
        end = self.source.index("reverify_published_immutable_release() {", start)
        refresher = self.source[start:end]
        self.assertIn('type(release.get(key)) is not bool', refresher)
        self.assertIn("datetime.fromisoformat", refresher)
        self.assertIn('release state has malformed assets', refresher)
        self.assertIn('release state has unsafe asset names', refresher)
        self.assertIn('release state is malformed; refusing to mutate', refresher)

    def test_immutable_release_path_never_edits_or_uploads(self) -> None:
        immutable = self.source.index('elif [[ "$RELEASE_IS_DRAFT" == "true" ]]')
        reverified = self.source.index(
            'echo "Existing immutable release was re-verified; metadata and notes were not modified."'
        )
        edit = self.source.index('gh release edit "$RELEASE_TAG"')
        upload = self.source.index('gh release upload "$RELEASE_TAG"')
        self.assertLess(edit, reverified)
        self.assertLess(upload, reverified)
        self.assertLess(immutable, edit)

    def test_release_requires_signed_schema_v6_manifest_before_promotion(self) -> None:
        manifest_verification = self.source.index("Verifying signed release metadata manifest")
        parser = self.source.index("scripts/verify_release_metadata.py")
        image_provenance = self.source.index("Verifying signed GitHub build provenance")
        self.assertLess(manifest_verification, parser)
        self.assertLess(parser, image_provenance)
        self.assertIn('METADATA_PROVENANCE_FILE="$WORK_DIR/enclave-release-metadata-provenance.jsonl"', self.source)
        self.assertIn('--expected-gcs-media-bucket "$EXPECTED_GCS_MEDIA_BUCKET"', self.source)
        self.assertIn(
            '--expected-gcs-legacy-media-bucket "$EXPECTED_GCS_LEGACY_MEDIA_BUCKET"',
            self.source,
        )
        self.assertIn("enclave-release-metadata-provenance.jsonl", self.source)
        self.assertIn(
            'if data["build_profile"] != "production":',
            self.metadata_verifier,
        )

    def test_apns_roll_preflight_reads_only_metadata_and_exact_iam(self) -> None:
        self.assertIn("gcloud secrets versions describe latest", self.source)
        self.assertIn("gcloud secrets get-iam-policy", self.source)
        self.assertIn('apns_latest_state" != "ENABLED"', self.source)
        self.assertIn("roles/secretmanager.secretAccessor", self.source)
        self.assertIn('serviceAccount:${ENCLAVE_RUN_SA_EMAIL}', self.source)
        self.assertNotIn("gcloud secrets versions access", self.source)
        self.assertNotIn("--impersonate-service-account", self.source)

    def test_release_reuses_exact_successful_main_ci_without_local_rebuild(self) -> None:
        verifier = self.source[
            self.source.index("verify_required_ci_success() {"):
            self.source.index('if [[ "$ROLLBACK_EXISTING" == "false"', self.source.index("verify_required_ci_success() {"))
        ]
        self.assertIn('--workflow build.yml', verifier)
        self.assertIn('--commit "$commit"', verifier)
        self.assertIn('--event push', verifier)
        self.assertIn('run.get("headBranch") == "main"', verifier)
        self.assertIn('run.get("headSha") == expected_commit', verifier)
        self.assertIn('job.get("name") == "CI"', verifier)
        self.assertIn('job.get("conclusion") != "success"', verifier)
        self.assertIn('REQUIRED_CI_COMMIT="$COMMIT"', self.source)
        self.assertIn('REQUIRED_CI_COMMIT="$REMOTE_TAG_COMMIT"', self.source)
        self.assertIn('verify_required_ci_success "$REQUIRED_CI_COMMIT"', self.source)
        ci_gate = self.source[
            self.source.index('if [[ "$ROLLBACK_EXISTING" == "false" ]]; then'):
            self.source.index('if [[ "$ROLLBACK_EXISTING" == "false" && "$RESUME_EXISTING" == "false"',
                              self.source.index('if [[ "$ROLLBACK_EXISTING" == "false" ]]; then'))
        ]
        self.assertIn('if [[ "$RESUME_EXISTING" == "true" ]]', ci_gate)
        self.assertNotIn("cargo fmt --all -- --check", self.source)
        self.assertNotIn("cargo test --locked", self.source)
        self.assertNotIn("cargo clippy --locked --all-targets -- -D warnings", self.source)

    def test_version_bump_syncs_only_the_root_lockfile_entry_without_building(self) -> None:
        bump_script = (ROOT / "scripts" / "bump_version.sh").read_text(encoding="utf-8")
        self.assertIn('name = "kioku-enclave"', bump_script)
        self.assertIn("cargo metadata --locked --no-deps --format-version 1", bump_script)
        self.assertNotIn("cargo check", bump_script)
        self.assertNotIn("cargo build", bump_script)

    def test_sccache_archive_has_an_independent_fixed_digest(self) -> None:
        expected_url = (
            "https://github.com/mozilla/sccache/releases/download/v0.17.0/"
            "sccache-v0.17.0-x86_64-unknown-linux-musl.tar.gz"
        )
        expected_digest = "67c4a96dd237c1f518f6b36083f270f9976d516f1e57fce891755ea782e50006"
        install = self.workflow[
            self.workflow.index("- name: Install digest-pinned sccache"):
            self.workflow.index("- name: Configure GitHub Actions compiler-cache backend")
        ]
        self.assertIn(f"SCCACHE_ARCHIVE_URL: {expected_url}", install)
        self.assertIn(f"SCCACHE_ARCHIVE_SHA256: {expected_digest}", install)
        self.assertNotIn(".sha256", install)
        self.assertNotIn("mozilla-actions/sccache-action", self.workflow)
        self.assertIn("sha256sum --check --strict", install)
        self.assertLess(install.index("sha256sum --check --strict"), install.index("tar --extract"))
        self.assertIn("--strip-components=1", install)
        self.assertIn('sccache" --version)" = "sccache 0.17.0"', install)
        self.assertIn("SCCACHE_GHA_VERSION: kioku-enclave-ci-v2", self.workflow)

        build_push = self.workflow[self.workflow.index("  build-push:"):]
        self.assertNotIn("RUSTC_WRAPPER", build_push)
        self.assertNotIn("SCCACHE_GHA_ENABLED", build_push)
        self.assertNotIn("sccache-v0.17.0", build_push)


class RequiredCiBehaviorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        source = RELEASE.read_text(encoding="utf-8")
        start = source.index("verify_required_ci_success() {")
        end = source.index('\nif [[ "$ROLLBACK_EXISTING" == "false"', start)
        cls.helper = source[start:end]

    def run_helper(
        self,
        runs: object,
        jobs: object,
        *,
        list_status: int = 0,
        view_status: int = 0,
    ) -> tuple[subprocess.CompletedProcess[str], str]:
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / "run-id"
            script = textwrap.dedent(
                f"""\
                set -euo pipefail
                REPOSITORY=owner/repository
                EXPECTED_COMMIT={commit}
                gh() {{
                  if [[ "$1 $2" == "run list" ]]; then
                    printf '%s' "$RUNS_JSON"
                    return "$LIST_STATUS"
                  fi
                  if [[ "$1 $2" == "run view" ]]; then
                    printf '%s' "$3" > "$CAPTURE_PATH"
                    printf '%s' "$JOBS_JSON"
                    return "$VIEW_STATUS"
                  fi
                  return 97
                }}
                {self.helper}
                verify_required_ci_success "$EXPECTED_COMMIT"
                """
            )
            completed = subprocess.run(
                ["bash", "-c", script],
                cwd=ROOT,
                env={
                    "PATH": "/usr/bin:/bin",
                    "RUNS_JSON": json.dumps(runs),
                    "JOBS_JSON": json.dumps(jobs),
                    "LIST_STATUS": str(list_status),
                    "VIEW_STATUS": str(view_status),
                    "CAPTURE_PATH": str(capture),
                },
                text=True,
                capture_output=True,
                check=False,
            )
            selected = capture.read_text(encoding="utf-8") if capture.exists() else ""
        return completed, selected

    @staticmethod
    def run(run_id: int, *, branch: str = "main", sha: str | None = None,
            status: str = "completed", conclusion: str = "success") -> dict[str, object]:
        return {
            "databaseId": run_id,
            "headBranch": branch,
            "headSha": sha or "a" * 40,
            "status": status,
            "conclusion": conclusion,
        }

    @staticmethod
    def ci_job(*, status: str = "completed", conclusion: str = "success") -> dict[str, str]:
        return {"name": "CI", "status": status, "conclusion": conclusion}

    def test_selects_latest_success_for_exact_main_commit(self) -> None:
        runs = [
            self.run(11),
            self.run(99, branch="feature"),
            self.run(98, sha="b" * 40),
            self.run(18, conclusion="failure"),
            self.run(15),
        ]
        completed, selected = self.run_helper(runs, {"jobs": [self.ci_job()]})
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(selected, "15")

    def test_rejects_nonexact_incomplete_and_failed_runs(self) -> None:
        cases = {
            "wrong branch": [self.run(1, branch="feature")],
            "wrong commit": [self.run(1, sha="b" * 40)],
            "incomplete": [self.run(1, status="in_progress", conclusion="")],
            "failed": [self.run(1, conclusion="failure")],
            "malformed": {"databaseId": 1},
        }
        for name, runs in cases.items():
            with self.subTest(name=name):
                completed, selected = self.run_helper(runs, {"jobs": [self.ci_job()]})
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(selected, "")

    def test_rejects_missing_duplicate_or_unsuccessful_ci_job(self) -> None:
        cases = {
            "missing": {"jobs": []},
            "duplicate": {"jobs": [self.ci_job(), self.ci_job()]},
            "failed": {"jobs": [self.ci_job(conclusion="failure")]},
            "incomplete": {"jobs": [self.ci_job(status="in_progress", conclusion="")]},
            "malformed": {"jobs": "not-a-list"},
        }
        for name, jobs in cases.items():
            with self.subTest(name=name):
                completed, selected = self.run_helper([self.run(7)], jobs)
                self.assertNotEqual(completed.returncode, 0)
                self.assertEqual(selected, "7")

    def test_cli_query_failures_are_rejected(self) -> None:
        completed, selected = self.run_helper([], {}, list_status=1)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(selected, "")
        self.assertIn("could not query required CI", completed.stderr)

        completed, selected = self.run_helper(
            [self.run(7)], {"jobs": [self.ci_job()]}, view_status=1
        )
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(selected, "7")
        self.assertIn("could not inspect required CI run", completed.stderr)


class VersionBumpBehaviorTests(unittest.TestCase):
    @staticmethod
    def cargo_lock(root_entries: int) -> str:
        root = textwrap.dedent(
            """\
            [[package]]
            name = "kioku-enclave"
            version = "1.2.3"
            """
        )
        dependency = textwrap.dedent(
            """\
            [[package]]
            name = "unchanged-dependency"
            version = "4.5.6"
            source = "registry+https://example.invalid/index"
            checksum = "unchanged"
            """
        )
        return "# This file is automatically @generated by Cargo.\nversion = 4\n\n" + root * root_entries + dependency

    def run_bump(self, root_entries: int) -> tuple[subprocess.CompletedProcess[str], str, str, bool]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scripts = root / "scripts"
            scripts.mkdir()
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text("", encoding="utf-8")
            shutil.copy2(ROOT / "scripts" / "bump_version.sh", scripts / "bump_version.sh")
            (root / "Cargo.toml").write_text(
                '[package]\nname = "kioku-enclave"\nversion = "1.2.3"\nedition = "2021"\n',
                encoding="utf-8",
            )
            (root / "Cargo.lock").write_text(self.cargo_lock(root_entries), encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "checkout", "-q", "-b", "release-test"], cwd=root, check=True)
            completed = subprocess.run(
                ["bash", "scripts/bump_version.sh", "2.0.0"],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )
            manifest = (root / "Cargo.toml").read_text(encoding="utf-8")
            lockfile = (root / "Cargo.lock").read_text(encoding="utf-8")
            target_exists = (root / "target").exists()
        return completed, manifest, lockfile, target_exists

    def test_updates_only_root_versions_without_creating_target(self) -> None:
        completed, manifest, lockfile, target_exists = self.run_bump(1)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn('version = "2.0.0"', manifest)
        self.assertIn('name = "kioku-enclave"\nversion = "2.0.0"', lockfile)
        self.assertIn('name = "unchanged-dependency"\nversion = "4.5.6"', lockfile)
        self.assertFalse(target_exists)

    def test_rejects_missing_or_duplicate_root_lockfile_entries(self) -> None:
        for count in (0, 2):
            with self.subTest(count=count):
                completed, _, lockfile, target_exists = self.run_bump(count)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(f"found {count}", completed.stderr)
                self.assertEqual(lockfile, self.cargo_lock(count))
                self.assertFalse(target_exists)


if __name__ == "__main__":
    unittest.main()
