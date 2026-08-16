#!/usr/bin/env python3
"""Hermetic contracts for detached frozen-source coordinator approvals."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts/verify_coordinator_advancement_receipt.py"
COMMIT = "a" * 40
ORIGIN = "b" * 40


class CoordinatorReceiptTests(unittest.TestCase):
    def test_signed_receipt_binds_repository_tag_commits_and_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            private = directory / "private.pem"
            public = directory / "public.pem"
            receipt = directory / "approval.json"
            signature = directory / "approval.sig"
            subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True)
            private.chmod(0o600)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True)
            public_der = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(public), "-pubout", "-outform", "DER"],
                check=True,
                capture_output=True,
            ).stdout
            fingerprint = hashlib.sha256(public_der).hexdigest()
            data = {
                "schema_version": 1,
                "repository": "owner/repository",
                "tag": "v1.2.3",
                "frozen_commit": COMMIT,
                "approved_origin_main": ORIGIN,
            }
            receipt.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            receipt.chmod(0o600)
            subprocess.run(
                [
                    "openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(private),
                    "-in", str(receipt), "-out", str(signature),
                ],
                check=True,
            )
            signature.chmod(0o600)
            command = [
                "python3", str(VERIFIER), "--receipt", str(receipt), "--signature", str(signature),
                "--public-key", str(public), "--expected-public-key-sha256", fingerprint,
                "--repository", "owner/repository", "--tag", "v1.2.3",
                "--frozen-commit", COMMIT, "--origin-main", ORIGIN,
            ]
            accepted = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            data["frozen_commit"] = "c" * 40
            receipt.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            rejected = subprocess.run(command, text=True, capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)


if __name__ == "__main__":
    unittest.main()
