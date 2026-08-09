#!/usr/bin/env bash
# Helper script to bump version in Cargo.toml, sync Cargo.lock, and stage the
# complete release candidate on a review branch. It never commits or pushes.

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

CURRENT_BRANCH="$(git symbolic-ref --quiet --short HEAD || true)"
if [[ -z "$CURRENT_BRANCH" ]]; then
  echo "Error: version bumps require a named review branch, not detached HEAD." >&2
  exit 3
fi
if [[ "$CURRENT_BRANCH" == "main" || "$CURRENT_BRANCH" == "master" ]]; then
  echo "Error: refusing to prepare a release directly on $CURRENT_BRANCH; use a PR branch." >&2
  exit 4
fi

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

git add -A
echo "Release candidate v${NEW_VERSION} is staged on ${CURRENT_BRANCH}."
echo "Inspect the staged diff, run all required checks, then commit and push this branch through a PR."
