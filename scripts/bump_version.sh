#!/usr/bin/env bash
# Helper script to bump version in Cargo.toml, sync Cargo.lock, commit, and push to main.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <MAJOR.MINOR.PATCH>" >&2
  echo "Example: $0 0.6.15" >&2
  exit 1
fi

NEW_VERSION="$1"
NEW_VERSION="${NEW_VERSION#v}"

if [[ ! "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Error: version must look like 1.2.3 or 1.2.3-rc.1" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "$REPO_ROOT"

echo "Bumping package version to $NEW_VERSION in Cargo.toml..."
python3 - "$NEW_VERSION" <<'PY'
import sys
import re

new_ver = sys.argv[1]
with open("Cargo.toml", "r") as f:
    content = f.read()

updated = re.sub(r'^(version\s*=\s*")[^"]+(")', f'\\g<1>{new_ver}\\g<2>', content, count=1, flags=re.MULTILINE)
with open("Cargo.toml", "w") as f:
    f.write(updated)
PY

echo "Syncing Cargo.lock..."
cargo check >/dev/null

git add Cargo.toml Cargo.lock
git commit -m "chore: prepare enclave v${NEW_VERSION} release"

echo "Pushing main to origin..."
git push origin main

echo "Version bump pushed cleanly! GitHub Actions will build the enclave image and publish release v${NEW_VERSION} automatically."
