#!/usr/bin/env python3
"""Isolated OpenSSL and fake-GitHub contracts for local release evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
import sys


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "scripts" / "local_build_evidence.py"
RELEASE = ROOT / "scripts" / "release.sh"
BUNDLE_VERIFIER = ROOT / "scripts" / "verify_local_evidence_bundle.py"
sys.path.insert(0, str(ROOT / "scripts"))
from test_select_build_configuration import environment  # noqa: E402
COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64


class LocalEvidenceTests(unittest.TestCase):
    def create_bundle(self, directory: Path) -> tuple[Path, Path, Path, str]:
        private = directory / "private.pem"
        public = directory / "public.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True)
        private.chmod(0o600)
        subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True)
        config = directory / "local.env"
        config_values = environment()
        config_values.pop("PATH", None)
        config_values.pop("GCP_WIF_PROVIDER", None)
        config_values.pop("GCP_SERVICE_ACCOUNT", None)
        config_values["LOCAL_GCP_IMPERSONATE_SERVICE_ACCOUNT"] = "local-builder@kioku-joerodriguez.iam.gserviceaccount.com"
        config.write_text("\n".join(f"{key}={value}" for key, value in sorted(config_values.items())) + "\n", encoding="utf-8")
        config.chmod(0o600)
        sbom = directory / "enclave-sbom.spdx.json"
        sbom.write_text('{"spdxVersion":"SPDX-2.3"}\n', encoding="utf-8")
        scan = directory / "enclave-scan.json"
        scan.write_text('{"matches":[]}\n', encoding="utf-8")
        metadata = directory / "enclave-release.json"
        image_repository = "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave"
        metadata.write_text(json.dumps({
            "schema_version": 8,
            "source_repository": "https://github.com/owner/repository",
            "source_ref": "v1.2.3", "source_commit": COMMIT,
            "image_uri": image_repository + ":release",
            "image_digest_uri": image_repository + "@" + DIGEST,
            "image_digest": DIGEST,
            "release_url": "https://github.com/owner/repository/releases/tag/v1.2.3",
            "build_profile": "production", "voice_quality_gate": "owner_only_unvalidated",
            "billing_enforcement_mode": "shadow", "gcs_bucket": "kioku-production-indexes",
            "gcs_media_bucket": "kioku-production-media", "gcs_legacy_media_bucket": "kioku-production-indexes",
            "archive_witness_shadow_mode": "off", "archive_witness_project_id": "",
            "archive_witness_project_number": "", "archive_witness_database_id": "",
            "archive_v3_shadow_runtime_mode": "off", "archive_v3_archive_bucket": "",
            "archive_v3_archive_gcs_project_number": "", "archive_v3_registry_kms_version": "",
            "archive_v3_witness_project_id": "", "archive_v3_witness_project_number": "",
            "archive_v3_witness_database_id": "",
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        evidence = directory / "enclave-local-build-evidence.json"
        subprocess.run(
            [
                "python3", str(EVIDENCE), "create", "--output", str(evidence),
                "--repository", "https://github.com/owner/repository", "--tag", "v1.2.3",
                "--commit", COMMIT, "--image-uri", image_repository + ":release",
                "--image-digest-uri", image_repository + "@" + DIGEST, "--image-digest", DIGEST,
                "--config", str(config), "--dockerfile", str(ROOT / "Dockerfile"),
                "--cargo-lock", str(ROOT / "Cargo.lock"), "--release-metadata", str(metadata),
                "--sbom", str(sbom), "--scan", str(scan),
                "--tool-version", "docker=27.0", "--tool-version", "syft=1.0",
                "--created-at", "2026-08-13T12:00:00Z", "--completed-at", "2026-08-13T12:01:00Z",
            ], check=True, cwd=ROOT,
        )
        signature = directory / "enclave-local-build-evidence.sig"
        subprocess.run(
            ["python3", str(EVIDENCE), "sign", "--manifest", str(evidence), "--signature", str(signature), "--private-key", str(private)],
            check=True, cwd=ROOT,
        )
        der = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(public), "-pubout", "-outform", "DER"],
            check=True, capture_output=True,
        ).stdout
        return evidence, signature, public, hashlib.sha256(der).hexdigest()

    def test_openssl_signature_requires_the_pinned_external_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, signature, public, fingerprint = self.create_bundle(Path(temporary))
            completed = subprocess.run(
                ["python3", str(EVIDENCE), "verify", "--manifest", str(evidence), "--signature", str(signature), "--public-key", str(public), "--expected-public-key-sha256", fingerprint],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["image_digest"], DIGEST)
            fingerprinted = subprocess.run(
                ["python3", str(EVIDENCE), "fingerprint", "--public-key", str(public)],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertEqual(fingerprinted.returncode, 0, fingerprinted.stderr)
            self.assertEqual(fingerprinted.stdout.strip(), fingerprint)
            wrong = subprocess.run(
                ["python3", str(EVIDENCE), "verify", "--manifest", str(evidence), "--signature", str(signature), "--public-key", str(public), "--expected-public-key-sha256", "c" * 64],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertNotEqual(wrong.returncode, 0)
            self.assertIn("external trust anchor", wrong.stderr)

    def test_group_readable_private_key_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence, _, _, _ = self.create_bundle(Path(temporary))
            private = Path(temporary) / "private.pem"
            private.chmod(0o640)
            completed = subprocess.run(
                ["python3", str(EVIDENCE), "sign", "--manifest", str(evidence), "--signature", str(Path(temporary) / "again.sig"), "--private-key", str(private)],
                cwd=ROOT, text=True, capture_output=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("exact mode 0600", completed.stderr)

    def test_bundle_verifier_binds_metadata_sbom_scan_source_and_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            _, _, public, fingerprint = self.create_bundle(directory)
            command = [
                "python3", str(BUNDLE_VERIFIER), "--evidence-dir", str(directory),
                "--public-key", str(public), "--expected-public-key-sha256", fingerprint,
                "--repository", "owner/repository", "--tag", "v1.2.3", "--commit", COMMIT,
                "--image-repository", "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave",
                "--expected-gcs-bucket", "kioku-production-indexes",
                "--expected-gcs-media-bucket", "kioku-production-media",
                "--expected-gcs-legacy-media-bucket", "kioku-production-indexes",
                "--config", str(directory / "local.env"),
            ]
            completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["metadata"]["image_digest"], DIGEST)
            deployment_contract = [
                "python3", str(BUNDLE_VERIFIER), "--evidence-dir", str(directory),
                "--repository", "https://github.com/owner/repository",
                "--release-tag", "v1.2.3", "--source-commit", COMMIT,
                "--image-digest-uri", "us-central1-docker.pkg.dev/kioku-joerodriguez/kioku/kioku-enclave@" + DIGEST,
                "--image-digest", DIGEST,
            ]
            deployment_environment = os.environ | {
                "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY": str(public),
                "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256": fingerprint,
            }
            deployed = subprocess.run(deployment_contract, cwd=ROOT, text=True, capture_output=True, env=deployment_environment)
            self.assertEqual(deployed.returncode, 0, deployed.stderr)
            (directory / "enclave-release.json").write_text("{}\n", encoding="utf-8")
            tampered = subprocess.run(command, cwd=ROOT, text=True, capture_output=True)
            self.assertNotEqual(tampered.returncode, 0)
            self.assertIn("exact enclave-release.json bytes", tampered.stderr)

    def test_fake_github_apply_publishes_only_after_evidence_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            evidence, signature, public, fingerprint = self.create_bundle(directory)
            fake_bin = directory / "bin"
            fake_bin.mkdir()
            git = fake_bin / "git"
            git.write_text(
                "#!/usr/bin/env bash\n"
                "if [[ \"$1 $2\" == 'branch --show-current' ]]; then echo main; exit 0; fi\n"
                "if [[ \"$1 $2\" == 'status --porcelain' ]]; then exit 0; fi\n"
                "if [[ \"$1 $2 $3\" == 'fetch origin main' ]]; then exit 0; fi\n"
                "if [[ \"$1 $2\" == 'rev-parse HEAD' || \"$1 $2\" == 'rev-parse origin/main' ]]; then echo '" + COMMIT + "'; exit 0; fi\n"
                "if [[ \"$1 $2 $3\" == 'rev-parse -q --verify' ]]; then exit 0; fi\n"
                "if [[ \"$1 $2 $3\" == 'rev-list -n 1' ]]; then echo '" + COMMIT + "'; exit 0; fi\n"
                "if [[ \"$1 $2\" == 'verify-tag --raw' ]]; then echo '[GNUPG:] VALIDSIG " + ("d" * 40) + "'; exit 0; fi\n"
                "if [[ \"$1 $2\" == 'push origin' ]]; then exit 0; fi\n"
                "echo \"unexpected fake git: $*\" >&2; exit 97\n",
                encoding="utf-8",
            )
            gh = fake_bin / "gh"
            gh.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$FAKE_GH_LOG\"\n"
                "if [[ \"$1\" == api ]]; then echo true; exit 0; fi\n"
                "if [[ \"$1 $2 $3\" == 'release view v1.2.3' ]]; then\n"
                "  if [[ -f \"$FAKE_GH_STATE\" ]]; then echo '{\"isDraft\":false,\"isImmutable\":true,\"isPrerelease\":false,\"assets\":[{\"name\":\"enclave-local-build-evidence.json\"},{\"name\":\"enclave-local-build-evidence.sig\"},{\"name\":\"enclave-release.json\"},{\"name\":\"enclave-sbom.spdx.json\"},{\"name\":\"enclave-scan.json\"}]}' ; exit 0; fi\n"
                "  exit 1\nfi\n"
                "if [[ \"$1 $2\" == 'release create' ]]; then touch \"$FAKE_GH_STATE\"; exit 0; fi\n"
                "exit 98\n",
                encoding="utf-8",
            )
            gcloud = fake_bin / "gcloud"
            gcloud.write_text(
                "#!/usr/bin/env bash\n"
                "printf '%s\\n' \"$*\" >> \"$FAKE_GCLOUD_LOG\"\n"
                "echo '" + DIGEST + "'\n",
                encoding="utf-8",
            )
            for executable in (git, gh, gcloud):
                executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            environment = os.environ | {
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "RELEASE_SIGNER_FINGERPRINT": "d" * 40,
                "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY": str(public),
                "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256": fingerprint,
                "FAKE_GH_LOG": str(directory / "gh.log"),
                "FAKE_GH_STATE": str(directory / "gh-state"),
                "FAKE_GCLOUD_LOG": str(directory / "gcloud.log"),
            }
            completed = subprocess.run(
                ["bash", str(RELEASE), "v1.2.3", "--evidence-dir", str(directory), "--config", str(directory / "local.env"), "--repository", "owner/repository", "--apply"],
                cwd=ROOT, text=True, capture_output=True, env=environment,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            gh_log = (directory / "gh.log").read_text(encoding="utf-8")
            self.assertIn(
                "release create v1.2.3",
                gh_log,
                f"stdout={completed.stdout!r} stderr={completed.stderr!r} files={sorted(path.name for path in directory.iterdir())}",
            )
            self.assertNotIn("workflow", gh_log)
            self.assertNotIn("dispatch", gh_log)
            self.assertNotIn("--prerelease", gh_log)
            gcloud_log = (directory / "gcloud.log").read_text(encoding="utf-8")
            self.assertIn("--impersonate-service-account=local-builder@", gcloud_log)
            self.assertEqual(evidence.name, "enclave-local-build-evidence.json")
            self.assertTrue(signature.is_file())


if __name__ == "__main__":
    unittest.main()
