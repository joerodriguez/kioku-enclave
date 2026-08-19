#!/usr/bin/env python3
"""Sign the ADR-0022 Phase-2 WAL-authority three-root authorization.

Solo-operator tool per docs/adr/0022-solo-operator-activation.md: the one
operator produces the exact 242-byte Phase-2 operator statement, 82-byte image
attestation, and 298-byte runtime admission that
`verify_pinned_phase2_authority` authenticates against the three pinned roots
under Phase-2-only domains (Phase-1 evidence can never replay), and signs each
with the matching operator-held private key.

- Writes six raw evidence files (payload + signature per root) into
  `--output-dir`.
- Prints only SHA-256 digests and the derived statement commitment; nothing
  secret is emitted.
- Private keys never leave their local files (defaults under
  `~/.local/state/kioku/adr0022-roots/`); signing shells out to
  `openssl pkeyutl` so key bytes never enter this process.
- Strictly offline: no network, no cloud, no repository mutation.

The runtime admission hard-codes the Phase-2 facts the verifier requires: the
canonical full reviewed mutation-set commitment over every `WalOperationKind`
ordinal (the in-enclave verifier compile-pins that set, so evidence produced
by a stale copy of this tool is refused rather than partially accepted), the
`PHASE2_WAL_AUTHORITY` marker, and acknowledge-after-witness-settlement.
"""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path

STATEMENT_DOMAIN = b"kioku/archive-v3/phase2-authority/operator-statement/v1\x00"
STATEMENT_COMMITMENT_DOMAIN = (
    b"kioku/archive-v3/phase2-authority/operator-statement-commitment/v1\x00"
)
IMAGE_ATTESTATION_DOMAIN = b"kioku/archive-v3/phase2-authority/image-attestation/v1\x00"
RUNTIME_ADMISSION_DOMAIN = b"kioku/archive-v3/phase2-authority/runtime-admission/v1\x00"
FULL_REVIEWED_MUTATION_SET_DOMAIN = (
    b"kioku/archive-v3/phase2-authority/authoritative-mutation-set/full-reviewed/v1\x00"
)

FORMAT_V1 = 1
PHASE2_WAL_AUTHORITY = 2
ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT = 2
OPERATOR_STATEMENT_BYTES = 242
IMAGE_ATTESTATION_BYTES = 82
RUNTIME_ADMISSION_BYTES = 298
DEFAULT_KEY_DIR = Path.home() / ".local/state/kioku/adr0022-roots"

# Every WalOperationKind ordinal, ascending, mirroring the compile-pinned
# reviewed set in src/archive_v3_advisory_owner/phase2_authority.rs. Adding a
# kind there forces a fresh reviewed commitment; evidence signed over this
# stale list is then refused by the verifier, never partially accepted.
FULL_REVIEWED_KIND_ORDINALS = tuple(range(1, 13))

STATEMENT_FIELDS = (
    ("--scope-id", 16),
    ("--user-id-commitment", 32),
    ("--archive-id", 16),
    ("--operation-id", 16),
    ("--operation-commitment", 32),
    ("--source-commitment", 32),
    ("--parity-commitment", 32),
    ("--terminal-witness-hash", 32),
    ("--release-image-digest", 32),
)
ADMISSION_FIELDS = (
    ("--deployment-target-commitment", 32),
    ("--maintenance-window-id", 16),
    ("--deployment-revision-commitment", 32),
    ("--challenge-commitment", 32),
    ("--monitoring-policy-commitment", 32),
    ("--rollback-policy-commitment", 32),
)


def fixed_bytes(name: str, value: str, length: int) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        raise SystemExit(f"{name}: not valid hex")
    if len(raw) != length:
        raise SystemExit(f"{name}: expected {length} bytes ({length * 2} hex chars)")
    if raw == bytes(length):
        raise SystemExit(f"{name}: zero value would be rejected by the verifier")
    return raw


def full_reviewed_mutation_set_commitment() -> bytes:
    hasher = hashlib.sha256()
    hasher.update(FULL_REVIEWED_MUTATION_SET_DOMAIN)
    hasher.update((1).to_bytes(2, "big"))
    hasher.update(len(FULL_REVIEWED_KIND_ORDINALS).to_bytes(2, "big"))
    for ordinal in FULL_REVIEWED_KIND_ORDINALS:
        hasher.update(ordinal.to_bytes(2, "big"))
    return hasher.digest()


def sign(key_path: Path, message: bytes) -> bytes:
    if not key_path.is_file():
        raise SystemExit(f"private key not found at {key_path}")
    with tempfile.NamedTemporaryFile() as msg:
        msg.write(message)
        msg.flush()
        result = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(key_path), "-rawin", "-in", msg.name],
            capture_output=True,
        )
    if result.returncode != 0:
        raise SystemExit("openssl signing failed")
    signature = result.stdout
    if len(signature) != 64:
        raise SystemExit("unexpected signature length")
    return signature


def raw_public_key(key_path: Path) -> bytes:
    result = subprocess.run(
        ["openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"],
        capture_output=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"cannot derive public key from {key_path}")
    der = result.stdout
    # An Ed25519 SubjectPublicKeyInfo is 44 bytes: 12-byte header, 32-byte key.
    if len(der) != 44:
        raise SystemExit(f"unexpected public key encoding from {key_path}")
    return der[-32:]


def build_statement(values: dict[str, bytes]) -> bytes:
    statement = FORMAT_V1.to_bytes(2, "big")
    for flag, _ in STATEMENT_FIELDS:
        statement += values[flag]
    assert len(statement) == OPERATOR_STATEMENT_BYTES
    return statement


def build_attestation(scope_id: bytes, commitment: bytes, image_digest: bytes) -> bytes:
    attestation = FORMAT_V1.to_bytes(2, "big") + scope_id + commitment + image_digest
    assert len(attestation) == IMAGE_ATTESTATION_BYTES
    return attestation


def build_admission(
    scope_id: bytes,
    commitment: bytes,
    image_digest: bytes,
    values: dict[str, bytes],
) -> bytes:
    admission = FORMAT_V1.to_bytes(2, "big")
    admission += scope_id
    admission += commitment
    admission += image_digest
    admission += full_reviewed_mutation_set_commitment()
    admission += values["--deployment-target-commitment"]
    admission += values["--maintenance-window-id"]
    admission += values["--deployment-revision-commitment"]
    admission += values["--challenge-commitment"]
    admission += values["--monitoring-policy-commitment"]
    admission += values["--rollback-policy-commitment"]
    admission += PHASE2_WAL_AUTHORITY.to_bytes(1, "big")
    admission += (0).to_bytes(2, "big")
    admission += ACKNOWLEDGE_AFTER_WITNESS_SETTLEMENT.to_bytes(1, "big")
    admission += (0).to_bytes(4, "big")
    assert len(admission) == RUNTIME_ADMISSION_BYTES
    return admission


def statement_commitment(statement: bytes, operator_public: bytes, signature: bytes) -> bytes:
    hasher = hashlib.sha256()
    hasher.update(STATEMENT_COMMITMENT_DOMAIN)
    hasher.update(operator_public)
    hasher.update(len(statement).to_bytes(4, "big"))
    hasher.update(statement)
    hasher.update(len(signature).to_bytes(4, "big"))
    hasher.update(signature)
    return hasher.digest()


def write_evidence(directory: Path, name: str, payload: bytes) -> None:
    path = directory / name
    path.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()
    print(f"{name} sha256={digest}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for flag, length in STATEMENT_FIELDS + ADMISSION_FIELDS:
        parser.add_argument(flag, required=True, help=f"{length}-byte hex value")
    parser.add_argument(
        "--operator-key",
        default=str(DEFAULT_KEY_DIR / "operator.key"),
        help="operator-approval private key path (never committed)",
    )
    parser.add_argument(
        "--image-key",
        default=str(DEFAULT_KEY_DIR / "image.key"),
        help="image-attestation private key path (never committed)",
    )
    parser.add_argument(
        "--deploy-key",
        default=str(DEFAULT_KEY_DIR / "deploy.key"),
        help="runtime-admission (deployment-observer) private key path (never committed)",
    )
    parser.add_argument(
        "--output-dir", required=True, help="directory receiving the six raw evidence files"
    )
    args = parser.parse_args()

    values: dict[str, bytes] = {}
    for flag, length in STATEMENT_FIELDS + ADMISSION_FIELDS:
        attr = flag.lstrip("-").replace("-", "_")
        values[flag] = fixed_bytes(flag, getattr(args, attr), length)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    statement = build_statement(values)
    operator_signature = sign(Path(args.operator_key), STATEMENT_DOMAIN + statement)
    operator_public = raw_public_key(Path(args.operator_key))
    commitment = statement_commitment(statement, operator_public, operator_signature)

    attestation = build_attestation(
        values["--scope-id"], commitment, values["--release-image-digest"]
    )
    attestation_signature = sign(Path(args.image_key), IMAGE_ATTESTATION_DOMAIN + attestation)

    admission = build_admission(
        values["--scope-id"], commitment, values["--release-image-digest"], values
    )
    admission_signature = sign(Path(args.deploy_key), RUNTIME_ADMISSION_DOMAIN + admission)

    write_evidence(output_dir, "phase2-operator-statement.bin", statement)
    write_evidence(output_dir, "phase2-operator-signature.bin", operator_signature)
    write_evidence(output_dir, "phase2-image-attestation.bin", attestation)
    write_evidence(output_dir, "phase2-image-attestation-signature.bin", attestation_signature)
    write_evidence(output_dir, "phase2-runtime-admission.bin", admission)
    write_evidence(output_dir, "phase2-runtime-admission-signature.bin", admission_signature)
    print(f"statement_commitment={commitment.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
