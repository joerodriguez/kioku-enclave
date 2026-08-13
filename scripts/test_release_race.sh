#!/usr/bin/env bash
# Execute release trust and state helpers with mocked Git/GitHub CLIs. This
# covers concurrent operator publication races and the exact signer anchor.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_SCRIPT="$SCRIPT_DIR/release.sh"
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TEMP_DIR"' EXIT

extract_helpers() {
  python3 - "$RELEASE_SCRIPT" <<'PY'
import sys

source = open(sys.argv[1], encoding="utf-8").read()
start = source.index("refresh_release_state_before_mutation() {")
end = source.index("refresh_release_state_before_mutation\nif ", start)
print(source[start:end])
PY
}

extract_signer_verifier() {
  python3 - "$RELEASE_SCRIPT" <<'PY'
import sys

source = open(sys.argv[1], encoding="utf-8").read()
start = source.index("verify_tag_signer() {")
end = source.index('if [[ -z "$REMOTE_TAG_COMMIT" ]]', start)
print(source[start:end])
PY
}

HELPERS="$TEMP_DIR/helpers.sh"
extract_helpers > "$HELPERS"
SIGNER_VERIFIER="$TEMP_DIR/signer-verifier.sh"
extract_signer_verifier > "$SIGNER_VERIFIER"

run_signer_case() {
  local case_name="$1"
  local actual_fingerprint="$2"
  local expect_success="$3"
  local case_dir="$TEMP_DIR/$case_name"
  mkdir -p "$case_dir"

  set +e
  ACTUAL_FINGERPRINT="$actual_fingerprint" SIGNER_VERIFIER="$SIGNER_VERIFIER" bash -s >"$case_dir/stdout" 2>"$case_dir/stderr" <<'SH'
set -euo pipefail
RELEASE_TAG="v1.2.3"
RELEASE_SIGNER_FINGERPRINT="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

git() {
  if [[ "$1" == "verify-tag" && "$2" == "--raw" && "$3" == "$RELEASE_TAG" ]]; then
    printf '[GNUPG:] VALIDSIG %s\n' "$ACTUAL_FINGERPRINT" >&2
    return 0
  fi
  return 92
}

source "$SIGNER_VERIFIER"
verify_tag_signer
SH
  status=$?
  set -e

  if [[ "$expect_success" == "true" ]]; then
    [[ "$status" -eq 0 ]] || { cat "$case_dir/stderr" >&2; echo "$case_name unexpectedly failed" >&2; return 1; }
  else
    [[ "$status" -ne 0 ]] || { echo "$case_name unexpectedly passed" >&2; return 1; }
    grep -q "was not signed by RELEASE_SIGNER_FINGERPRINT" "$case_dir/stderr"
  fi
}

run_race_case() {
  local case_name="$1"
  local remote_suffix="$2"
  local expect_success="$3"
  local release_json="$4"
  local case_dir="$TEMP_DIR/$case_name"
  local expected_names
  mkdir -p "$case_dir/work" "$case_dir/remote"
  expected_names=$'enclave-provenance.jsonl\nenclave-release-metadata-provenance.jsonl\nenclave-release.json\nenclave-sbom-attestation.jsonl\nenclave-sbom.spdx.json'
  while IFS= read -r name; do
    printf 'verified-%s\n' "$name" > "$case_dir/work/$name"
    printf '%s-%s\n' "$remote_suffix" "$name" > "$case_dir/remote/$name"
  done <<< "$expected_names"
  if [[ "$remote_suffix" == "verified" ]]; then
    cp "$case_dir/work"/* "$case_dir/remote/"
  fi

  set +e
  CASE_DIR="$case_dir" HELPERS="$HELPERS" RELEASE_JSON="$release_json" bash -s >"$case_dir/stdout" 2>"$case_dir/stderr" <<'SH'
set -euo pipefail
RELEASE_TAG="v1.2.3"
REPOSITORY="owner/repository"
WORK_DIR="$CASE_DIR/work"
EXPECTED_ASSET_NAMES=$'enclave-provenance.jsonl\nenclave-release-metadata-provenance.jsonl\nenclave-release.json\nenclave-sbom-attestation.jsonl\nenclave-sbom.spdx.json'
EXPECTED_ASSETS_CSV="$(tr '\n' ',' <<< "$EXPECTED_ASSET_NAMES" | sed 's/,$//')"
EXPECTED_PRERELEASE=false

gh() {
  case "$1 $2" in
    "release view")
      printf '%s' "$RELEASE_JSON"
      ;;
    "release download")
      printf 'download\n' >> "$CASE_DIR/gh-calls"
      local_pattern=""
      local_dir=""
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --pattern) local_pattern="$2"; shift 2 ;;
          --dir) local_dir="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      cp "$CASE_DIR/remote/$local_pattern" "$local_dir/$local_pattern"
      ;;
    "release create"|"release edit"|"release upload")
      printf 'MUTATION %s %s\n' "$1" "$2" >> "$CASE_DIR/gh-calls"
      exit 91
      ;;
    *)
      printf 'unexpected gh invocation: %s %s\n' "$1" "$2" >&2
      exit 92
      ;;
  esac
}

source "$HELPERS"
refresh_release_state_before_mutation
if [[ "$RELEASE_EXISTS" == "true" && "$RELEASE_IS_DRAFT" == "false" ]]; then
  reverify_published_immutable_release
fi
SH
  status=$?
  set -e

  if [[ "$expect_success" == "true" ]]; then
    [[ "$status" -eq 0 ]] || { cat "$case_dir/stderr" >&2; echo "$case_name unexpectedly failed" >&2; return 1; }
  else
    [[ "$status" -ne 0 ]] || { cat "$case_dir/stderr" >&2; echo "$case_name unexpectedly passed" >&2; return 1; }
  fi
  if grep -q 'MUTATION' "$case_dir/gh-calls" 2>/dev/null; then
    echo "$case_name attempted a release mutation" >&2
    return 1
  fi
}

run_post_check_create_race_case() {
  local case_name="$1"
  local expect_success="$2"
  local release_json="$3"
  local case_dir="$TEMP_DIR/$case_name"
  local expected_names
  mkdir -p "$case_dir/work" "$case_dir/remote"
  expected_names=$'enclave-provenance.jsonl\nenclave-release-metadata-provenance.jsonl\nenclave-release.json\nenclave-sbom-attestation.jsonl\nenclave-sbom.spdx.json'
  while IFS= read -r name; do
    printf 'verified-%s\n' "$name" > "$case_dir/work/$name"
  done <<< "$expected_names"
  cp "$case_dir/work"/* "$case_dir/remote/"

  set +e
  CASE_DIR="$case_dir" HELPERS="$HELPERS" RELEASE_JSON="$release_json" bash -s >"$case_dir/stdout" 2>"$case_dir/stderr" <<'SH'
set -euo pipefail
RELEASE_TAG="v1.2.3"
REPOSITORY="owner/repository"
WORK_DIR="$CASE_DIR/work"
NOTES_FILE="$CASE_DIR/notes.md"
RELEASE_ASSETS=("$WORK_DIR/enclave-release.json")
PRERELEASE_ARGS=(--prerelease=false)
EXPECTED_ASSET_NAMES=$'enclave-provenance.jsonl\nenclave-release-metadata-provenance.jsonl\nenclave-release.json\nenclave-sbom-attestation.jsonl\nenclave-sbom.spdx.json'
EXPECTED_ASSETS_CSV="$(tr '\n' ',' <<< "$EXPECTED_ASSET_NAMES" | sed 's/,$//')"
EXPECTED_PRERELEASE=false

gh() {
  case "$1 $2" in
    "release create")
      printf 'CREATE_ATTEMPT\n' >> "$CASE_DIR/gh-calls"
      return 1
      ;;
    "release view")
      printf '%s' "$RELEASE_JSON"
      ;;
    "release download")
      local_pattern=""
      local_dir=""
      while [[ $# -gt 0 ]]; do
        case "$1" in
          --pattern) local_pattern="$2"; shift 2 ;;
          --dir) local_dir="$2"; shift 2 ;;
          *) shift ;;
        esac
      done
      cp "$CASE_DIR/remote/$local_pattern" "$local_dir/$local_pattern"
      ;;
    "release edit"|"release upload")
      printf 'UNSAFE_MUTATION %s %s\n' "$1" "$2" >> "$CASE_DIR/gh-calls"
      exit 91
      ;;
    *)
      printf 'unexpected gh invocation: %s %s\n' "$1" "$2" >&2
      exit 92
      ;;
  esac
}

source "$HELPERS"
create_release_or_reverify_publication_race
SH
  status=$?
  set -e

  if [[ "$expect_success" == "true" ]]; then
    [[ "$status" -eq 0 ]] || { cat "$case_dir/stderr" >&2; echo "$case_name unexpectedly failed" >&2; return 1; }
  else
    [[ "$status" -ne 0 ]] || { cat "$case_dir/stderr" >&2; echo "$case_name unexpectedly passed" >&2; return 1; }
  fi
  [[ "$(grep -c '^CREATE_ATTEMPT$' "$case_dir/gh-calls")" -eq 1 ]]
  if grep -q 'UNSAFE_MUTATION' "$case_dir/gh-calls"; then
    echo "post-check create race attempted edit/upload" >&2
    return 1
  fi
}

published_release_json='{"isDraft":false,"isImmutable":true,"isPrerelease":false,"publishedAt":"2026-08-10T00:00:00Z","assets":[{"name":"enclave-provenance.jsonl"},{"name":"enclave-release-metadata-provenance.jsonl"},{"name":"enclave-release.json"},{"name":"enclave-sbom-attestation.jsonl"},{"name":"enclave-sbom.spdx.json"}]}'

# A cryptographically valid tag from another signer is not enough. The sole
# publisher requires the exact out-of-band fingerprint before any mutation.
run_signer_case trusted_signer AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA true
run_signer_case generic_verified_wrong_signer BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB false

# A raced immutable release with identical expected assets is reverified and
# takes no create/edit/upload path.
run_race_case immutable_identical verified true "$published_release_json"
# A raced immutable release whose content differs is rejected before any
# mutation, even though its asset names and release flags look valid.
run_race_case immutable_mismatched attacker false "$published_release_json"
# Hostile or malformed release states fail closed before any mutation.
run_race_case malformed_json verified false '{'
run_race_case malformed_timestamp verified false "${published_release_json/2026-08-10T00:00:00Z/not-a-date}"
run_race_case mismatched_prerelease verified false "${published_release_json/\"isPrerelease\":false/\"isPrerelease\":true}"
run_race_case unexpected_asset verified false "${published_release_json/\"enclave-sbom.spdx.json\"/\"unexpected.json\"}"
run_race_case duplicate_asset verified false "${published_release_json/\"enclave-sbom.spdx.json\"/\"enclave-release.json\"}"
# Publication after the pre-mutation refresh still converges safely: the one
# failed create attempt is followed by exact immutable re-verification, never
# by edit or upload.
run_post_check_create_race_case post_check_create_race true "$published_release_json"
# A failed create followed by a draft observation remains incomplete for an
# explicit later resume and never falls through to draft edit/upload here.
run_post_check_create_race_case post_check_draft false '{"isDraft":true,"isImmutable":false,"isPrerelease":false,"publishedAt":null,"assets":[]}'

echo "release publication race mock tests passed"
