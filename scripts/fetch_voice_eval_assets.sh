#!/usr/bin/env bash
# Fetch the exact licensed archives named by an ADR-0016 release manifest.
# Media is required to live outside the public source checkout.

set -euo pipefail

usage() {
  echo "Usage: $0 <release-manifest.json> <absolute-output-directory>"
}

if [[ $# -ne 2 || "$2" != /* ]]; then
  usage
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MANIFEST_PATH="$1"
OUTPUT_DIRECTORY="$2"

for command_name in cargo curl jq; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Error: required command not found: $command_name" >&2
    exit 1
  fi
done
if command -v shasum >/dev/null 2>&1; then
  SHA256_COMMAND=(shasum -a 256)
elif command -v sha256sum >/dev/null 2>&1; then
  SHA256_COMMAND=(sha256sum)
else
  echo "Error: shasum or sha256sum is required." >&2
  exit 1
fi

if [[ ! -s "$MANIFEST_PATH" ]]; then
  echo "Error: manifest is missing or empty: $MANIFEST_PATH" >&2
  exit 1
fi
MANIFEST_PATH="$(cd "$(dirname "$MANIFEST_PATH")" && pwd -P)/$(basename "$MANIFEST_PATH")"

if [[ ! -d "$OUTPUT_DIRECTORY" ]]; then
  echo "Error: create the private output directory before running this command." >&2
  exit 1
fi
OUTPUT_DIRECTORY="$(cd "$OUTPUT_DIRECTORY" && pwd -P)"
case "$OUTPUT_DIRECTORY" in
  /|"${REPO_ROOT}"|"${REPO_ROOT}/"*)
    echo "Error: evaluation media must be stored outside the public repository." >&2
    exit 1
    ;;
esac

cd "$REPO_ROOT"
cargo run --locked --quiet -- \
  --validate-voice-eval-manifest "$MANIFEST_PATH"

temporary_path=""
cleanup() {
  if [[ -n "$temporary_path" && -e "$temporary_path" ]]; then
    rm -f -- "$temporary_path"
  fi
}
trap cleanup EXIT

while IFS=$'\t' read -r source_id archive_url expected_sha256; do
  archive_path="${OUTPUT_DIRECTORY}/${source_id}.archive"
  if [[ -e "$archive_path" ]]; then
    actual_sha256="$("${SHA256_COMMAND[@]}" "$archive_path" | awk '{print $1}')"
    if [[ "$actual_sha256" != "$expected_sha256" ]]; then
      echo "Error: existing archive has the wrong SHA-256: $archive_path" >&2
      exit 1
    fi
    echo "Verified existing licensed archive: $source_id"
    continue
  fi

  temporary_path="$(mktemp "${OUTPUT_DIRECTORY}/.${source_id}.download.XXXXXX")"
  curl \
    --fail \
    --location \
    --proto '=https' \
    --proto-redir '=https' \
    --retry 3 \
    --show-error \
    --silent \
    --tlsv1.2 \
    --output "$temporary_path" \
    "$archive_url"
  actual_sha256="$("${SHA256_COMMAND[@]}" "$temporary_path" | awk '{print $1}')"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    echo "Error: downloaded archive SHA-256 mismatch for $source_id" >&2
    exit 1
  fi
  mv -n "$temporary_path" "$archive_path"
  if [[ -e "$temporary_path" ]]; then
    echo "Error: archive appeared concurrently; refusing to replace it: $archive_path" >&2
    exit 1
  fi
  temporary_path=""
  echo "Fetched and verified licensed archive: $source_id"
done < <(jq -er '.sources[] | [.id, .archive_url, .archive_sha256] | @tsv' "$MANIFEST_PATH")

echo "All licensed evaluation archives are present and hash-verified in $OUTPUT_DIRECTORY"
