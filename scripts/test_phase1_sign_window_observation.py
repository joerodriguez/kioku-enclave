#!/usr/bin/env python3
"""Contracts for the Phase-1 window-observation signer (throwaway keys only)."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "phase1_sign_window_observation.py"
DOMAIN = b"kioku/archive-v3/phase1-window-observation/v1\x00"


def run_signer(key: Path, **overrides):
    args = {
        "--window-id": "11" * 16,
        "--intent-commitment": "22" * 32,
        "--challenge-commitment": "33" * 32,
        "--zero-replica-digest": "44" * 32,
        "--sequence": "1",
        "--timestamp-ticks": "1500",
    }
    args.update(overrides)
    cmd = [sys.executable, "-B", str(SCRIPT), "--key", str(key)]
    for flag, value in args.items():
        cmd.extend([flag, value])
    return subprocess.run(cmd, capture_output=True, text=True)


class SignerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.key = Path(self.tmp.name) / "throwaway.key"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ed25519", "-out", str(self.key)],
            check=True,
            capture_output=True,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_signature_verifies_over_domain_separated_payload(self):
        result = run_signer(self.key)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = dict(line.split("=", 1) for line in result.stdout.strip().splitlines())
        payload = bytes.fromhex(lines["payload_hex"])
        signature = bytes.fromhex(lines["signature_hex"])
        self.assertEqual(len(payload), 130)
        self.assertEqual(payload[0:2], (1).to_bytes(2, "big"))
        self.assertEqual(len(signature), 64)

        with tempfile.NamedTemporaryFile() as msg, tempfile.NamedTemporaryFile() as sig:
            msg.write(DOMAIN + payload)
            msg.flush()
            sig.write(signature)
            sig.flush()
            pub = Path(self.tmp.name) / "throwaway.pub"
            subprocess.run(
                ["openssl", "pkey", "-in", str(self.key), "-pubout", "-out", str(pub)],
                check=True,
                capture_output=True,
            )
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
                text=True,
            )
            self.assertEqual(verify.returncode, 0, verify.stderr)
            # Tampered domain must not verify: signature binds the domain prefix.
            msg.seek(0)
            msg.write(b"X")
            msg.flush()
            verify_bad = subprocess.run(
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
            self.assertNotEqual(verify_bad.returncode, 0)

    def test_zero_values_and_bad_lengths_are_refused(self):
        for flag, bad in [
            ("--window-id", "00" * 16),
            ("--intent-commitment", "00" * 32),
            ("--challenge-commitment", "00" * 32),
            ("--zero-replica-digest", "00" * 32),
            ("--window-id", "11" * 15),
            ("--intent-commitment", "zz" * 32),
            ("--sequence", "0"),
            ("--timestamp-ticks", "0"),
        ]:
            result = run_signer(self.key, **{flag: bad})
            self.assertNotEqual(result.returncode, 0, f"{flag}={bad} must be refused")

    def test_missing_key_fails_closed(self):
        result = run_signer(Path(self.tmp.name) / "absent.key")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("payload_hex", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
