#!/usr/bin/env bash
# Publish an auditable open-source enclave release and optionally request a
# production VM roll in the deployment repository.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOYMENT_REPO="${DEPLOYMENT_REPO:-joerodriguez/kioku}"
ROLL=false

usage() {
  echo "Usage: $0 <vMAJOR.MINOR.PATCH> [--roll]"
  echo ""
  echo "  Publishes a source tag, waits for the public image build, and creates"
  echo "  a GitHub Release containing the exact image digest and build metadata."
  echo "  --roll also dispatches the deployment repo's approval-gated VM roll."
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit 2
fi

RELEASE_TAG="$1"
if [[ $# -eq 2 ]]; then
  if [[ "$2" != "--roll" ]]; then
    usage
    exit 2
  fi
  ROLL=true
fi

if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Error: release tag must look like v1.2.3 or v1.2.3-rc.1" >&2
  exit 2
fi

for command_name in git gh cargo python3; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Error: required command not found: $command_name" >&2
    exit 1
  fi
done

cd "$REPO_ROOT"
gh auth status >/dev/null

REPOSITORY="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
VISIBILITY="$(gh repo view --json visibility --jq .visibility)"
if [[ "$VISIBILITY" != "PUBLIC" ]]; then
  echo "Error: enclave releases must be published from a public repository (found: $VISIBILITY)." >&2
  echo "       Complete the one-time public-repository checklist in RELEASING.md first." >&2
  exit 1
fi

REQUIRED_REPO_VARIABLES=(
  GCP_WIF_PROVIDER GCP_SERVICE_ACCOUNT
  ENCLAVE_KMS_PROJECT ENCLAVE_KMS_LOCATION ENCLAVE_KMS_KEY_RING
  ENCLAVE_KMS_KEY ENCLAVE_GCS_BUCKET ENCLAVE_RUN_SA_EMAIL
  ENCLAVE_AUDIENCE ENCLAVE_ATTEST_STS_AUDIENCE
  GOOGLE_DESKTOP_CLIENT_ID GOOGLE_WEB_CLIENT_ID ALLOWED_EMAILS BASE_URL
  VERTEX_PROJECT VERTEX_LOCATION VERTEX_MODEL
  ENCLAVE_ACME ENCLAVE_ACME_DIRECTORY ENCLAVE_ACME_CONTACT
)
CONFIGURED_VARIABLES="$(gh variable list --repo "$REPOSITORY" --json name --jq '.[].name')"
for variable_name in "${REQUIRED_REPO_VARIABLES[@]}"; do
  if ! grep -qx "$variable_name" <<< "$CONFIGURED_VARIABLES"; then
    echo "Error: required GitHub Actions variable is not configured: $variable_name" >&2
    echo "       Configure the release variables listed in RELEASING.md before tagging." >&2
    exit 1
  fi
done
CURRENT_BRANCH="$(git branch --show-current)"
if [[ "$CURRENT_BRANCH" != "main" ]]; then
  echo "Error: enclave releases must be cut from main (currently $CURRENT_BRANCH)." >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: working tree is not clean. Commit or stash changes before releasing." >&2
  exit 1
fi

echo "Fetching main and release tags..."
git fetch origin main --tags
COMMIT="$(git rev-parse HEAD)"
if [[ "$COMMIT" != "$(git rev-parse origin/main)" ]]; then
  echo "Error: local main must exactly match origin/main before releasing." >&2
  exit 1
fi

REMOTE_TAG_COMMIT="$(git rev-list -n 1 "$RELEASE_TAG" 2>/dev/null || true)"
ROLLBACK_EXISTING=false
if [[ -n "$REMOTE_TAG_COMMIT" && "$REMOTE_TAG_COMMIT" != "$COMMIT" ]]; then
  if [[ "$ROLL" == "true" ]] && gh release view "$RELEASE_TAG" --repo "$REPOSITORY" >/dev/null 2>&1; then
    ROLLBACK_EXISTING=true
    echo "Using previously published $RELEASE_TAG at $REMOTE_TAG_COMMIT for rollback."
  else
    echo "Error: $RELEASE_TAG already points to a different commit." >&2
    echo "       Add --roll only if you intend to roll back to its existing public release." >&2
    exit 1
  fi
fi

if [[ "$ROLLBACK_EXISTING" == "false" ]]; then
  echo "Running release checks..."
  cargo fmt --all -- --check
  cargo test --locked
  cargo clippy --locked -- -D warnings
fi

if [[ -z "$REMOTE_TAG_COMMIT" ]]; then
  git tag -a "$RELEASE_TAG" -m "Kioku enclave $RELEASE_TAG"
  git push origin "$RELEASE_TAG"
  REMOTE_TAG_COMMIT="$COMMIT"
  echo "Published source tag $RELEASE_TAG at $COMMIT."
else
  echo "Source tag $RELEASE_TAG already exists at $REMOTE_TAG_COMMIT; resuming release."
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
METADATA_FILE="$WORK_DIR/enclave-release.json"

# Public release assets are the durable source for an existing release or
# rollback. CI artifacts are only the handoff mechanism while publishing a new
# release and may expire.
if gh release view "$RELEASE_TAG" --repo "$REPOSITORY" >/dev/null 2>&1; then
  gh release download "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --pattern enclave-release.json \
    --dir "$WORK_DIR" || true
fi

if [[ ! -s "$METADATA_FILE" ]]; then
  echo "Waiting for the tagged image build to appear..."
  RUN_ID=""
  RUN_URL=""
  for _ in $(seq 1 60); do
    RUN_JSON="$(gh run list \
      --repo "$REPOSITORY" \
      --workflow build.yml \
      --commit "$REMOTE_TAG_COMMIT" \
      --event push \
      --limit 20 \
      --json databaseId,headBranch,url)"
    RUN_RESULT="$(printf '%s' "$RUN_JSON" | python3 -c '
import json, sys
tag = sys.argv[1]
for run in json.load(sys.stdin):
    if run.get("headBranch") == tag:
        print(f"{run[\"databaseId\"]}\t{run[\"url\"]}")
        break
' "$RELEASE_TAG")"
    if [[ -n "$RUN_RESULT" ]]; then
      RUN_ID="${RUN_RESULT%%$'\t'*}"
      RUN_URL="${RUN_RESULT#*$'\t'}"
      break
    fi
    sleep 2
  done

  if [[ -z "$RUN_ID" ]]; then
    echo "Error: no tagged build appeared. The tag is published; inspect Actions and rerun this command." >&2
    exit 1
  fi

  echo "Watching build: $RUN_URL"
  gh run watch "$RUN_ID" --repo "$REPOSITORY" --exit-status

  ARTIFACT_NAME="enclave-release-metadata-${RUN_ID}"
  gh run download "$RUN_ID" \
    --repo "$REPOSITORY" \
    --name "$ARTIFACT_NAME" \
    --dir "$WORK_DIR"
else
  echo "Using durable metadata from the existing public release."
fi

if [[ ! -s "$METADATA_FILE" ]]; then
  echo "Error: build did not produce enclave-release.json" >&2
  exit 1
fi

RELEASE_METADATA="$(python3 - "$METADATA_FILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    data = json.load(handle)
keys = ("source_ref", "source_commit", "image_uri", "image_digest_uri", "image_digest", "build_url")
print("\t".join(data[key] for key in keys))
PY
)"
IFS=$'\t' read -r BUILT_REF BUILT_COMMIT IMAGE_URI DIGEST_URI DIGEST BUILD_URL <<< "$RELEASE_METADATA"

if [[ "$BUILT_REF" != "$RELEASE_TAG" || "$BUILT_COMMIT" != "$REMOTE_TAG_COMMIT" ]]; then
  echo "Error: build metadata does not match the requested source tag and commit." >&2
  exit 1
fi
if [[ ! "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Error: build returned an invalid image digest: $DIGEST" >&2
  exit 1
fi

NOTES_FILE="$WORK_DIR/release-notes.md"
printf '%s\n' \
  "Open-source Kioku enclave release **${RELEASE_TAG}**." \
  "" \
  "| Field | Value |" \
  "|---|---|" \
  "| Source commit | \`${REMOTE_TAG_COMMIT}\` |" \
  "| Image | \`${DIGEST_URI}\` |" \
  "| Image digest | \`${DIGEST}\` |" \
  "| Build | [GitHub Actions run](${BUILD_URL}) |" \
  "" \
  "The digest is the attestation anchor used by the deployment's KMS policy." \
  "See README.md for the trust boundary and current reproducibility caveats." \
  > "$NOTES_FILE"

if gh release view "$RELEASE_TAG" --repo "$REPOSITORY" >/dev/null 2>&1; then
  gh release edit "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --title "Kioku enclave $RELEASE_TAG" \
    --notes-file "$NOTES_FILE"
else
  gh release create "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --title "Kioku enclave $RELEASE_TAG" \
    --notes-file "$NOTES_FILE"
fi
gh release upload "$RELEASE_TAG" "$METADATA_FILE" \
  --repo "$REPOSITORY" \
  --clobber

echo "Public release: https://github.com/${REPOSITORY}/releases/tag/${RELEASE_TAG}"
echo "Digest-pinned image: $DIGEST_URI"

if [[ "$ROLL" == "true" ]]; then
  echo "Dispatching the approval-gated production roll in $DEPLOYMENT_REPO..."
  gh workflow run enclave.yml \
    --repo "$DEPLOYMENT_REPO" \
    --ref main \
    -f "release_tag=$RELEASE_TAG" \
    -f "enclave_image=$DIGEST_URI" \
    -f "enclave_image_digest=$DIGEST"
  echo "Roll requested. Approve and monitor it at:"
  echo "https://github.com/${DEPLOYMENT_REPO}/actions/workflows/enclave.yml"
else
  echo "Production was not changed. To request the gated roll:"
  echo "  $0 $RELEASE_TAG --roll"
fi
