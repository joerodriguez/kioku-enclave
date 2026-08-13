#!/usr/bin/env bash
# Kept as the executable release-race entrypoint for the local pipeline.
# The Python contract uses temporary Ed25519 keys and fake GitHub/GCP CLIs,
# so it exercises an apply-shaped publication without network access.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/test_local_build_evidence.py"
