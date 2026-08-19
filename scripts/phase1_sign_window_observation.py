#!/usr/bin/env python3
"""Sign one ADR-0022 Phase-1 window observation as the deployment-observer root.

Solo-operator tool per docs/adr/0022-solo-operator-activation.md: the operator, who
stopped serving themselves, signs the exact 130-byte v1 observation payload the
in-enclave `LiveDeploymentWindowObserver` verifies (domain-separated Ed25519).

- Emits `payload_hex` and `signature_hex` on stdout; nothing secret is printed.
- The private key never leaves the operator's local key file (default
  `~/.local/state/kioku/adr0022-roots/deploy.key`); signing shells out to
  `openssl pkeyutl` so the key bytes never enter this process.
- Strictly offline: no network, no cloud, no repository mutation.

All field values are hex strings of exact length; the tool refuses zero values the
verifier would reject, so an unusable observation cannot be produced.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

DOMAIN = b"kioku/archive-v3/phase1-window-observation/v1\x00"
FORMAT_V1 = 1
PAYLOAD_BYTES = 2 + 16 + 32 + 32 + 32 + 8 + 8


def fixed_bytes(name: str, value: str, length: int, allow_zero: bool = False) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise SystemExit(f"{name}: not valid hex")
    if len(raw) != length:
        raise SystemExit(f"{name}: expected {length} bytes ({length * 2} hex chars)")
    if not allow_zero and raw == bytes(length):
        raise SystemExit(f"{name}: zero value would be rejected by the verifier")
    return raw


def build_payload(args: argparse.Namespace) -> bytes:
    payload = FORMAT_V1.to_bytes(2, "big")
    payload += fixed_bytes("--window-id", args.window_id, 16)
    payload += fixed_bytes("--intent-commitment", args.intent_commitment, 32)
    payload += fixed_bytes("--challenge-commitment", args.challenge_commitment, 32)
    payload += fixed_bytes("--zero-replica-digest", args.zero_replica_digest, 32)
    if args.sequence < 1:
        raise SystemExit("--sequence: must be >= 1")
    payload += args.sequence.to_bytes(8, "big")
    if args.timestamp_ticks < 1:
        raise SystemExit("--timestamp-ticks: must be >= 1")
    payload += args.timestamp_ticks.to_bytes(8, "big")
    assert len(payload) == PAYLOAD_BYTES
    return payload


def sign(key_path: Path, message: bytes) -> bytes:
    if not key_path.is_file():
        raise SystemExit(f"deployment-observer key not found at {key_path}")
    with tempfile.NamedTemporaryFile() as msg:
        msg.write(message)
        msg.flush()
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(key_path),
                "-rawin",
                "-in",
                msg.name,
            ],
            capture_output=True,
        )
    if result.returncode != 0:
        raise SystemExit("openssl signing failed")
    signature = result.stdout
    if len(signature) != 64:
        raise SystemExit("unexpected signature length")
    return signature


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--window-id", required=True, help="16-byte hex maintenance window ID")
    parser.add_argument(
        "--intent-commitment", required=True, help="32-byte hex window intent commitment"
    )
    parser.add_argument(
        "--challenge-commitment", required=True, help="32-byte hex scope challenge commitment"
    )
    parser.add_argument(
        "--zero-replica-digest",
        required=True,
        help="32-byte hex zero-serving-replica witness digest",
    )
    parser.add_argument("--sequence", type=int, required=True, help="monotonic sequence >= 1")
    parser.add_argument(
        "--timestamp-ticks", type=int, required=True, help="trusted timestamp within the window"
    )
    parser.add_argument(
        "--key",
        default=str(Path.home() / ".local/state/kioku/adr0022-roots/deploy.key"),
        help="deployment-observer private key path (never committed)",
    )
    args = parser.parse_args()

    payload = build_payload(args)
    signature = sign(Path(args.key), DOMAIN + payload)
    print(f"payload_hex={payload.hex()}")
    print(f"signature_hex={signature.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
