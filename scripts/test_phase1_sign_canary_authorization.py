#!/usr/bin/env python3
"""Contracts for the Phase-1 canary-authorization signer (throwaway keys only)."""

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "phase1_sign_canary_authorization.py"
STATEMENT_DOMAIN = b"kioku/archive-v3/advisory-canary/operator-statement/v1\x00"
ATTESTATION_DOMAIN = b"kioku/archive-v3/advisory-canary/image-attestation/v1\x00"
ADMISSION_DOMAIN = b"kioku/archive-v3/advisory-canary/runtime-admission/v1\x00"
EMPTY_SET_DOMAIN = b"kioku/archive-v3/advisory-canary/authoritative-mutation-set/empty/v1\x00"

ARGS = {
    "--scope-id": "11" * 16,
    "--user-id-commitment": "22" * 32,
    "--archive-id": "33" * 16,
    "--operation-id": "44" * 16,
    "--operation-commitment": "55" * 32,
    "--source-commitment": "66" * 32,
    "--parity-commitment": "77" * 32,
    "--terminal-witness-hash": "88" * 32,
    "--release-image-digest": "99" * 32,
    "--deployment-target-commitment": "aa" * 32,
    "--maintenance-window-id": "bb" * 16,
    "--deployment-revision-commitment": "cc" * 32,
    "--challenge-commitment": "dd" * 32,
    "--monitoring-policy-commitment": "ee" * 32,
    "--rollback-policy-commitment": "0f" * 32,
}


def openssl_verify(pub: Path, domain: bytes, payload: bytes, signature: bytes) -> bool:
    with tempfile.NamedTemporaryFile() as msg, tempfile.NamedTemporaryFile() as sig:
        msg.write(domain + payload)
        msg.flush()
        sig.write(signature)
        sig.flush()
        verify = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(pub),
                "-rawin",
                "-in",
                msg.name,
                "-sigfile",
                sig.name,
            ],
            capture_output=True,
        )
        return verify.returncode == 0


class CanaryAuthorizationSignerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.keys = {}
        self.pubs = {}
        for name in ("operator", "image", "deploy"):
            key = Path(self.tmp.name) / f"{name}.key"
            subprocess.run(
                ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(key)],
                check=True,
                capture_output=True,
            )
            pub = Path(self.tmp.name) / f"{name}.pub"
            subprocess.run(
                ["openssl", "pkey", "-in", str(key), "-pubout", "-out", str(pub)],
                check=True,
                capture_output=True,
            )
            self.keys[name] = key
            self.pubs[name] = pub
        self.out = Path(self.tmp.name) / "evidence"

    def tearDown(self):
        self.tmp.cleanup()

    def run_signer(self, **overrides):
        args = dict(ARGS)
        args.update(overrides)
        cmd = [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--operator-key",
            str(self.keys["operator"]),
            "--image-key",
            str(self.keys["image"]),
            "--deploy-key",
            str(self.keys["deploy"]),
            "--output-dir",
            str(self.out),
        ]
        for flag, value in args.items():
            cmd.extend([flag, value])
        return subprocess.run(cmd, capture_output=True, text=True)

    def test_evidence_files_match_verifier_shapes_and_signatures_verify(self):
        result = self.run_signer()
        self.assertEqual(result.returncode, 0, result.stderr)
        statement = (self.out / "operator-statement.bin").read_bytes()
        statement_sig = (self.out / "operator-signature.bin").read_bytes()
        attestation = (self.out / "image-attestation.bin").read_bytes()
        attestation_sig = (self.out / "image-attestation-signature.bin").read_bytes()
        admission = (self.out / "runtime-admission.bin").read_bytes()
        admission_sig = (self.out / "runtime-admission-signature.bin").read_bytes()

        self.assertEqual(len(statement), 242)
        self.assertEqual(len(attestation), 82)
        self.assertEqual(len(admission), 298)
        for signature in (statement_sig, attestation_sig, admission_sig):
            self.assertEqual(len(signature), 64)

        # Statement layout: format prefix then the nine exact fields in order.
        self.assertEqual(statement[0:2], (1).to_bytes(2, "big"))
        self.assertEqual(statement[2:18], bytes.fromhex(ARGS["--scope-id"]))
        self.assertEqual(statement[210:242], bytes.fromhex(ARGS["--release-image-digest"]))

        # Each signature verifies under its own domain and root, and never
        # under another root or the wrong domain.
        self.assertTrue(
            openssl_verify(self.pubs["operator"], STATEMENT_DOMAIN, statement, statement_sig)
        )
        self.assertTrue(
            openssl_verify(self.pubs["image"], ATTESTATION_DOMAIN, attestation, attestation_sig)
        )
        self.assertTrue(
            openssl_verify(self.pubs["deploy"], ADMISSION_DOMAIN, admission, admission_sig)
        )
        self.assertFalse(
            openssl_verify(self.pubs["image"], STATEMENT_DOMAIN, statement, statement_sig)
        )
        self.assertFalse(
            openssl_verify(self.pubs["operator"], ATTESTATION_DOMAIN, statement, statement_sig)
        )

        # The attestation and admission embed the derived statement commitment
        # over the operator public key, statement, and signature.
        operator_pub_der = subprocess.run(
            ["openssl", "pkey", "-in", str(self.keys["operator"]), "-pubout", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout
        commitment = hashlib.sha256(
            b"kioku/archive-v3/advisory-canary/operator-statement-commitment/v1\x00"
            + operator_pub_der[-32:]
            + statement
            + statement_sig
        ).digest()
        self.assertEqual(attestation[18:50], commitment)
        self.assertEqual(admission[18:50], commitment)
        expected_line = f"statement_commitment={commitment.hex()}"
        self.assertIn(expected_line, result.stdout)

        # The admission pins the Phase-1 facts: the exact empty mutation-set
        # commitment, the PHASE1_ADVISORY marker, legacy-only acknowledgement,
        # and zero reserved fields.
        empty_set = hashlib.sha256(
            EMPTY_SET_DOMAIN + (1).to_bytes(2, "big") + (0).to_bytes(2, "big")
        ).digest()
        self.assertEqual(admission[82:114], empty_set)
        self.assertEqual(admission[290], 1)
        self.assertEqual(admission[291:293], b"\x00\x00")
        self.assertEqual(admission[293], 1)
        self.assertEqual(admission[294:298], b"\x00\x00\x00\x00")

    def test_zero_values_and_bad_lengths_are_refused(self):
        for flag, bad in [
            ("--scope-id", "00" * 16),
            ("--user-id-commitment", "00" * 32),
            ("--release-image-digest", "00" * 32),
            ("--maintenance-window-id", "bb" * 15),
            ("--challenge-commitment", "zz" * 32),
        ]:
            result = self.run_signer(**{flag: bad})
            self.assertNotEqual(result.returncode, 0, f"{flag}={bad} must be refused")
            self.assertFalse((self.out / "operator-statement.bin").exists())

    def test_missing_key_fails_closed(self):
        missing = Path(self.tmp.name) / "absent.key"
        cmd = [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--operator-key",
            str(missing),
            "--image-key",
            str(self.keys["image"]),
            "--deploy-key",
            str(self.keys["deploy"]),
            "--output-dir",
            str(self.out),
        ]
        for flag, value in ARGS.items():
            cmd.extend([flag, value])
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.out / "operator-statement.bin").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
