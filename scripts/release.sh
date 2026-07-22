#!/usr/bin/env bash
# Publish an auditable open-source enclave release and optionally request a
# production VM roll in the deployment repository.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOYMENT_REPO="${DEPLOYMENT_REPO:-}"
RELEASE_SIGNER_FINGERPRINT="${RELEASE_SIGNER_FINGERPRINT:-}"
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

if [[ "$ROLL" == "true" && ! "$DEPLOYMENT_REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "Error: --roll requires DEPLOYMENT_REPO=owner/repository." >&2
  exit 2
fi

# This is the operator's out-of-band trust anchor for source tags. Accept
# either an OpenPGP fingerprint or an SSH SHA256 key fingerprint.
if [[ ! "$RELEASE_SIGNER_FINGERPRINT" =~ ^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}|SHA256:[A-Za-z0-9+/=]+)$ ]]; then
  echo "Error: RELEASE_SIGNER_FINGERPRINT must contain the trusted OpenPGP or SSH signing-key fingerprint." >&2
  exit 2
fi
if [[ "$RELEASE_SIGNER_FINGERPRINT" != SHA256:* ]]; then
  RELEASE_SIGNER_FINGERPRINT="$(printf '%s' "$RELEASE_SIGNER_FINGERPRINT" | tr '[:lower:]' '[:upper:]')"
fi

for command_name in git gh gcloud cargo python3; do
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
if [[ "$(gh api -H 'X-GitHub-Api-Version: 2026-03-10' \
  "repos/${REPOSITORY}/immutable-releases" --jq .enabled)" != "true" ]]; then
  echo "Error: GitHub immutable releases must be enabled before publishing." >&2
  echo "       See RELEASING.md for the one-time repository setup." >&2
  exit 1
fi

REQUIRED_REPO_VARIABLES=(
  GCP_WIF_PROVIDER GCP_SERVICE_ACCOUNT
  GCP_PROJECT_ID GCP_REGION AR_REPOSITORY IMAGE_NAME
  ENCLAVE_KMS_PROJECT ENCLAVE_KMS_LOCATION ENCLAVE_KMS_KEY_RING
  ENCLAVE_KMS_KEY ENCLAVE_GCS_BUCKET ENCLAVE_RUN_SA_EMAIL
  ENCLAVE_AUDIENCE ENCLAVE_ATTEST_STS_AUDIENCE
  GOOGLE_DESKTOP_CLIENT_ID GOOGLE_WEB_CLIENT_ID BASE_URL WEB_ORIGIN
  VERTEX_PROJECT VERTEX_LOCATION VERTEX_MODEL
  ENCLAVE_ACME ENCLAVE_ACME_DIRECTORY
)
CONFIGURED_VARIABLES="$(gh variable list --repo "$REPOSITORY" --json name --jq '.[].name')"
for variable_name in "${REQUIRED_REPO_VARIABLES[@]}"; do
  if ! grep -qx "$variable_name" <<< "$CONFIGURED_VARIABLES"; then
    echo "Error: required GitHub Actions variable is not configured: $variable_name" >&2
    echo "       Configure the release variables listed in RELEASING.md before tagging." >&2
    exit 1
  fi
done
REQUIRED_REPO_SECRETS=(ALLOWED_EMAILS ENCLAVE_ACME_CONTACT)
CONFIGURED_SECRETS="$(gh secret list --repo "$REPOSITORY" --json name --jq '.[].name')"
for secret_name in "${REQUIRED_REPO_SECRETS[@]}"; do
  if ! grep -qx "$secret_name" <<< "$CONFIGURED_SECRETS"; then
    echo "Error: required privacy-sensitive GitHub Actions secret is not configured: $secret_name" >&2
    exit 1
  fi
done

PROJECT_ID="$(gh variable get GCP_PROJECT_ID --repo "$REPOSITORY")"
REGION="$(gh variable get GCP_REGION --repo "$REPOSITORY")"
AR_REPOSITORY="$(gh variable get AR_REPOSITORY --repo "$REPOSITORY")"
IMAGE_NAME="$(gh variable get IMAGE_NAME --repo "$REPOSITORY")"
REGISTRY_HOST="${REGION}-docker.pkg.dev"

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

# `gh attestation verify oci://...` resolves the image manifest even with a
# local bundle, so the release operator needs read-only Artifact Registry auth.
# Configure the standard Docker credential helper and prove repository access
# before creating a source tag.
gcloud artifacts repositories describe "$AR_REPOSITORY" \
  --project "$PROJECT_ID" \
  --location "$REGION" >/dev/null
gcloud auth configure-docker "$REGISTRY_HOST" --quiet >/dev/null

REMOTE_TAG_COMMIT="$(git rev-list -n 1 "$RELEASE_TAG" 2>/dev/null || true)"
RELEASE_EXISTS=false
RELEASE_IS_DRAFT=false
RELEASE_IS_IMMUTABLE=false
RELEASE_IS_PRERELEASE=false
RELEASE_PUBLISHED_AT=""
if RELEASE_STATE="$(gh release view "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json isDraft,isImmutable,isPrerelease,publishedAt \
  --jq '[.isDraft, .isImmutable, .isPrerelease, (.publishedAt // "")] | @tsv' 2>/dev/null)"; then
  RELEASE_EXISTS=true
  IFS=$'\t' read -r RELEASE_IS_DRAFT RELEASE_IS_IMMUTABLE RELEASE_IS_PRERELEASE RELEASE_PUBLISHED_AT <<< "$RELEASE_STATE"
fi

ROLLBACK_EXISTING=false
RESUME_EXISTING=false
if [[ -n "$REMOTE_TAG_COMMIT" && "$REMOTE_TAG_COMMIT" != "$COMMIT" ]]; then
  if [[ "$ROLL" == "true" && "$RELEASE_EXISTS" == "true" && "$RELEASE_IS_DRAFT" == "false" && "$RELEASE_IS_IMMUTABLE" == "true" && "$RELEASE_IS_PRERELEASE" == "false" && -n "$RELEASE_PUBLISHED_AT" ]]; then
    ROLLBACK_EXISTING=true
    echo "Using previously published $RELEASE_TAG at $REMOTE_TAG_COMMIT for rollback."
  elif [[ "$RELEASE_EXISTS" == "false" || "$RELEASE_IS_DRAFT" == "true" ]]; then
    RESUME_EXISTING=true
    echo "Resuming incomplete $RELEASE_TAG at $REMOTE_TAG_COMMIT."
  else
    echo "Error: $RELEASE_TAG already points to a different commit." >&2
    echo "       Add --roll only if you intend to roll back to its existing public release." >&2
    exit 1
  fi
fi

if [[ -n "$REMOTE_TAG_COMMIT" ]] && ! git merge-base --is-ancestor "$REMOTE_TAG_COMMIT" origin/main; then
  echo "Error: $RELEASE_TAG is not an ancestor of origin/main; refusing release or rollback." >&2
  exit 1
fi

if [[ -n "$REMOTE_TAG_COMMIT" ]]; then
  PACKAGE_VERSION="$(git show "${RELEASE_TAG}:Cargo.toml" | python3 -c '
import re, sys
text = sys.stdin.read()
section = re.search(r"(?ms)^\[package\]\s*$\n(.*?)(?=^\[|\Z)", text)
match = re.search(r"(?m)^version\s*=\s*\"([^\"]+)\"\s*$", section.group(1) if section else "")
if not match:
    raise SystemExit("tagged Cargo.toml has no package version")
print(match.group(1))
')"
else
  PACKAGE_VERSION="$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"
fi
if [[ "$RELEASE_TAG" != "v${PACKAGE_VERSION}" ]]; then
  echo "Error: Cargo package version ${PACKAGE_VERSION} does not match ${RELEASE_TAG}." >&2
  exit 1
fi

if [[ "$ROLLBACK_EXISTING" == "false" && "$RESUME_EXISTING" == "false" ]]; then
  echo "Running release checks..."
  cargo fmt --all -- --check
  cargo test --locked
  cargo clippy --locked --all-targets -- -D warnings
fi

verify_tag_signer() {
  local verification actual_fingerprints
  if ! verification="$(git verify-tag --raw "$RELEASE_TAG" 2>&1)"; then
    echo "Error: ${RELEASE_TAG} does not have a valid signed-tag signature." >&2
    return 1
  fi
  if [[ "$RELEASE_SIGNER_FINGERPRINT" == SHA256:* ]]; then
    actual_fingerprints="$(printf '%s\n' "$verification" | sed -nE 's/^.* key (SHA256:[A-Za-z0-9+\/=]+).*$/\1/p')"
  else
    # Accept the exact signing subkey or its primary key fingerprint; GnuPG
    # emits both on VALIDSIG when a signing subkey is used.
    actual_fingerprints="$(printf '%s\n' "$verification" | awk '
      $1 == "[GNUPG:]" && $2 == "VALIDSIG" {
        print toupper($3)
        if (NF >= 12) print toupper($NF)
      }
    ')"
  fi
  if [[ -z "$actual_fingerprints" ]] || ! grep -qxF "$RELEASE_SIGNER_FINGERPRINT" <<< "$actual_fingerprints"; then
    echo "Error: ${RELEASE_TAG} was not signed by RELEASE_SIGNER_FINGERPRINT." >&2
    return 1
  fi
}

if [[ -z "$REMOTE_TAG_COMMIT" ]]; then
  git tag -s "$RELEASE_TAG" -m "Kioku enclave $RELEASE_TAG"
  verify_tag_signer
  git push origin "$RELEASE_TAG"
  REMOTE_TAG_COMMIT="$COMMIT"
  echo "Published source tag $RELEASE_TAG at $COMMIT."
else
  echo "Source tag $RELEASE_TAG already exists at $REMOTE_TAG_COMMIT; resuming release."
  verify_tag_signer
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
METADATA_FILE="$WORK_DIR/enclave-release.json"
PROVENANCE_FILE="$WORK_DIR/enclave-provenance.jsonl"
SBOM_FILE="$WORK_DIR/enclave-sbom.spdx.json"
SBOM_ATTESTATION_FILE="$WORK_DIR/enclave-sbom-attestation.jsonl"

# Immutable public release assets are the durable source for a re-verification
# or rollback. A draft is repaired only from its tagged CI build; draft assets
# are never trusted as a fallback and are overwritten before publication.
if [[ "$RELEASE_EXISTS" == "true" && "$RELEASE_IS_DRAFT" == "false" ]]; then
  if [[ "$RELEASE_IS_IMMUTABLE" != "true" || -z "$RELEASE_PUBLISHED_AT" ]]; then
    echo "Error: existing release is not a published immutable GitHub release." >&2
    exit 1
  fi
  if [[ "$ROLL" == "true" && "$RELEASE_IS_PRERELEASE" == "true" ]]; then
    echo "Error: refusing to roll a prerelease to production." >&2
    exit 1
  fi
  gh release download "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --pattern 'enclave-*.json*' \
    --dir "$WORK_DIR"
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
        print("{}\t{}".format(run["databaseId"], run["url"]))
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
keys = ("schema_version", "source_repository", "source_ref", "source_commit", "image_uri", "image_digest_uri", "image_digest", "build_url")
print("\t".join(str(data[key]) for key in keys))
PY
)"
IFS=$'\t' read -r SCHEMA_VERSION SOURCE_REPOSITORY BUILT_REF BUILT_COMMIT IMAGE_URI DIGEST_URI DIGEST BUILD_URL <<< "$RELEASE_METADATA"

if [[ "$SCHEMA_VERSION" != "1" || "$SOURCE_REPOSITORY" != "https://github.com/${REPOSITORY}" ]]; then
  echo "Error: build metadata has an unexpected schema or source repository." >&2
  exit 1
fi
if [[ "$BUILT_REF" != "$RELEASE_TAG" || "$BUILT_COMMIT" != "$REMOTE_TAG_COMMIT" ]]; then
  echo "Error: build metadata does not match the requested source tag and commit." >&2
  exit 1
fi
if [[ ! "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "Error: build returned an invalid image digest: $DIGEST" >&2
  exit 1
fi

EXPECTED_IMAGE_REPOSITORY="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPOSITORY}/${IMAGE_NAME}"
if [[ "$IMAGE_URI" != "${EXPECTED_IMAGE_REPOSITORY}:"* ]]; then
  echo "Error: image URI is outside the configured Artifact Registry repository." >&2
  exit 1
fi
if [[ "$DIGEST_URI" != "${EXPECTED_IMAGE_REPOSITORY}@${DIGEST}" ]]; then
  echo "Error: digest-qualified image URI does not match the configured repository and digest." >&2
  exit 1
fi
if [[ "$BUILD_URL" != "https://github.com/${REPOSITORY}/actions/runs/"* ]]; then
  echo "Error: build URL is outside this source repository." >&2
  exit 1
fi
REGISTRY_DIGEST="$(gcloud artifacts docker images describe "$DIGEST_URI" \
  --project "$PROJECT_ID" \
  --format='value(image_summary.digest)')"
if [[ "$REGISTRY_DIGEST" != "$DIGEST" ]]; then
  echo "Error: Artifact Registry did not resolve the expected image digest." >&2
  exit 1
fi
if [[ ! -s "$PROVENANCE_FILE" ]]; then
  echo "Error: release is missing enclave-provenance.jsonl." >&2
  exit 1
fi
if [[ ! -s "$SBOM_FILE" || ! -s "$SBOM_ATTESTATION_FILE" ]]; then
  echo "Error: release is missing its SBOM or signed SBOM attestation." >&2
  exit 1
fi
SBOM_VERSION="$(python3 - "$SBOM_FILE" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle).get("spdxVersion", ""))
PY
)"
if [[ ! "$SBOM_VERSION" =~ ^SPDX-[0-9]+\.[0-9]+$ ]]; then
  echo "Error: release SBOM has an invalid SPDX version: $SBOM_VERSION" >&2
  exit 1
fi
SBOM_PREDICATE_TYPE="https://spdx.dev/Document/v${SBOM_VERSION#SPDX-}"

echo "Verifying signed GitHub build provenance..."
gh attestation verify "oci://${DIGEST_URI}" \
  --repo "$REPOSITORY" \
  --bundle "$PROVENANCE_FILE" \
  --deny-self-hosted-runners \
  --signer-workflow "${REPOSITORY}/.github/workflows/build.yml" \
  --source-digest "$REMOTE_TAG_COMMIT" \
  --source-ref "refs/tags/${RELEASE_TAG}" >/dev/null
SBOM_VERIFICATION_FILE="$WORK_DIR/verified-sbom-attestation.json"
gh attestation verify "oci://${DIGEST_URI}" \
  --repo "$REPOSITORY" \
  --bundle "$SBOM_ATTESTATION_FILE" \
  --deny-self-hosted-runners \
  --predicate-type "$SBOM_PREDICATE_TYPE" \
  --signer-workflow "${REPOSITORY}/.github/workflows/build.yml" \
  --source-digest "$REMOTE_TAG_COMMIT" \
  --source-ref "refs/tags/${RELEASE_TAG}" \
  --format json > "$SBOM_VERIFICATION_FILE"

# The standalone SBOM is convenient for people and scanners, but it is only
# trustworthy if its normalized JSON is byte-for-byte equivalent to the
# predicate inside the verified DSSE statement.
python3 - "$SBOM_FILE" "$SBOM_VERIFICATION_FILE" "$DIGEST" "$SBOM_PREDICATE_TYPE" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as handle:
    standalone = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    verification = json.load(handle)

digest = sys.argv[3].removeprefix("sha256:")
predicate_type = sys.argv[4]
matching_predicates = []
for result in verification:
    statement = result.get("verificationResult", {}).get("statement", {})
    if statement.get("predicateType") != predicate_type:
        continue
    subjects = statement.get("subject", [])
    if not any(subject.get("digest", {}).get("sha256") == digest for subject in subjects):
        continue
    matching_predicates.append(statement.get("predicate"))

if not matching_predicates:
    raise SystemExit("verified SBOM attestation did not contain the expected image subject")
if standalone not in matching_predicates:
    raise SystemExit("standalone SBOM does not match the verified SBOM predicate")
PY

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

RELEASE_ASSETS=(
  "$METADATA_FILE"
  "$PROVENANCE_FILE"
  "$SBOM_FILE"
  "$SBOM_ATTESTATION_FILE"
)
EXPECTED_ASSET_NAMES="$(printf '%s\n' \
  enclave-provenance.jsonl \
  enclave-release.json \
  enclave-sbom-attestation.jsonl \
  enclave-sbom.spdx.json | sort)"
EXPECTED_PRERELEASE=false
PRERELEASE_ARGS=(--prerelease=false)
if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  EXPECTED_PRERELEASE=true
  PRERELEASE_ARGS=(--prerelease)
fi

if [[ "$RELEASE_EXISTS" == "false" ]]; then
  # gh creates a draft internally, uploads every asset, and only then publishes;
  # this is required because immutable releases lock assets at publication.
  gh release create "$RELEASE_TAG" "${RELEASE_ASSETS[@]}" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --title "Kioku enclave $RELEASE_TAG" \
    --notes-file "$NOTES_FILE" \
    "${PRERELEASE_ARGS[@]}"
elif [[ "$RELEASE_IS_DRAFT" == "true" ]]; then
  # Repair an interrupted draft only when it contains no unexpected assets.
  while IFS= read -r asset_name; do
    [[ -z "$asset_name" ]] && continue
    if ! grep -qxF "$asset_name" <<< "$EXPECTED_ASSET_NAMES"; then
      echo "Error: draft release contains unexpected asset: $asset_name" >&2
      exit 1
    fi
  done < <(gh release view "$RELEASE_TAG" --repo "$REPOSITORY" --json assets --jq '.assets[].name')
  gh release edit "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --title "Kioku enclave $RELEASE_TAG" \
    --notes-file "$NOTES_FILE" \
    "${PRERELEASE_ARGS[@]}"
  gh release upload "$RELEASE_TAG" "${RELEASE_ASSETS[@]}" \
    --repo "$REPOSITORY" \
    --clobber
  UPLOADED_ASSET_NAMES="$(gh release view "$RELEASE_TAG" --repo "$REPOSITORY" --json assets --jq '.assets[].name' | sort)"
  if [[ "$UPLOADED_ASSET_NAMES" != "$EXPECTED_ASSET_NAMES" ]]; then
    echo "Error: draft release does not contain exactly the expected assets." >&2
    exit 1
  fi
  gh release edit "$RELEASE_TAG" --repo "$REPOSITORY" --draft=false
else
  echo "Existing immutable release was re-verified; metadata and notes were not modified."
fi

FINAL_RELEASE_STATE="$(gh release view "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json isDraft,isImmutable,isPrerelease,publishedAt,assets \
  --jq '[.isDraft, .isImmutable, .isPrerelease, (.publishedAt // ""), ([.assets[].name] | sort | join(","))] | @tsv')"
IFS=$'\t' read -r FINAL_IS_DRAFT FINAL_IS_IMMUTABLE FINAL_IS_PRERELEASE FINAL_PUBLISHED_AT FINAL_ASSETS <<< "$FINAL_RELEASE_STATE"
EXPECTED_ASSETS_CSV="$(tr '\n' ',' <<< "$EXPECTED_ASSET_NAMES" | sed 's/,$//')"
if [[ "$FINAL_IS_DRAFT" != "false" || "$FINAL_IS_IMMUTABLE" != "true" || -z "$FINAL_PUBLISHED_AT" ]]; then
  echo "Error: release was not published immutably." >&2
  exit 1
fi
if [[ "$FINAL_ASSETS" != "$EXPECTED_ASSETS_CSV" ]]; then
  echo "Error: immutable release does not contain exactly the expected assets." >&2
  exit 1
fi
if [[ "$FINAL_IS_PRERELEASE" != "$EXPECTED_PRERELEASE" ]]; then
  echo "Error: release prerelease state does not match its tag." >&2
  exit 1
fi
if [[ "$ROLL" == "true" && "$FINAL_IS_PRERELEASE" == "true" ]]; then
  echo "Error: refusing to roll a prerelease to production." >&2
  exit 1
fi
gh release verify "$RELEASE_TAG" --repo "$REPOSITORY" >/dev/null

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
