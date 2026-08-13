#!/usr/bin/env bash
# Publish an auditable open-source enclave release and optionally request a
# production VM roll in the deployment repository.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOYMENT_REPO="${DEPLOYMENT_REPO:-}"
RELEASE_SIGNER_FINGERPRINT="${RELEASE_SIGNER_FINGERPRINT:-}"
ROLL=false
EXPECTED_VOICE_QUALITY_GATE=""
EXPECTED_BILLING_ENFORCEMENT_MODE=""

usage() {
  echo "Usage: $0 <vMAJOR.MINOR.PATCH> [--roll]"
  echo ""
  echo "  Publishes a source tag, waits for the public image build, and creates"
  echo "  a GitHub Release containing the exact image digest and build metadata."
  echo "  --roll also dispatches the deployment repo's confirmed VM roll."
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

PROBE_RELEASE=false
PACKAGE_RELEASE_TAG="$RELEASE_TAG"
if [[ "$RELEASE_TAG" =~ ^(v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*))-witness-probe\.([1-9][0-9]*)$ ]]; then
  PROBE_RELEASE=true
  PACKAGE_RELEASE_TAG="${BASH_REMATCH[1]}"
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

# The same checked-in parser used by the build and metadata verifier decides
# whether this exact tag may carry probe-v1. This runs before any tag/release
# mutation. The probe can never enter the production roll path.
SELECTED_ARCHIVE_WITNESS_MODE="$(python3 - "$RELEASE_TAG" <<'PY'
import sys
from pathlib import Path
from scripts.archive_witness_probe_config import load_probe_config, select_probe_config

selected = select_probe_config(
    load_probe_config(Path("config/archive-witness-probe.json")),
    profile="production",
    source_ref=sys.argv[1],
)
print(selected.mode)
PY
)"
if [[ "$SELECTED_ARCHIVE_WITNESS_MODE" == "probe-v1" && "$PROBE_RELEASE" != "true" ]]; then
  echo "Error: probe-v1 requires an exact vX.Y.Z-witness-probe.N prerelease tag." >&2
  exit 1
fi
if [[ "$SELECTED_ARCHIVE_WITNESS_MODE" == "probe-v1" && "$ROLL" == "true" ]]; then
  echo "Error: refusing to roll an archive witness probe release to production." >&2
  exit 1
fi

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
  ENCLAVE_KMS_KEY ENCLAVE_GCS_BUCKET ENCLAVE_GCS_MEDIA_BUCKET ENCLAVE_GCS_LEGACY_MEDIA_BUCKET ENCLAVE_RUN_SA_EMAIL
  ENCLAVE_AUDIENCE ENCLAVE_ATTEST_STS_AUDIENCE
  GOOGLE_DESKTOP_CLIENT_ID GOOGLE_IOS_CLIENT_ID GOOGLE_WEB_CLIENT_ID BASE_URL WEB_ORIGIN
  APNS_TEAM_ID APNS_PRODUCTION_KEY_ID APNS_SANDBOX_KEY_ID
  REVIEWER_AUTH_API_KEY REVIEWER_AUTH_UID REVIEWER_AUTH_EMAIL
  VERTEX_PROJECT VERTEX_LOCATION VERTEX_MODEL
  BILLING_SERVICE_URL BILLING_SERVICE_AUDIENCE BILLING_ENFORCEMENT_MODE
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
EXPECTED_GCS_BUCKET="$(gh variable get ENCLAVE_GCS_BUCKET --repo "$REPOSITORY")"
EXPECTED_GCS_MEDIA_BUCKET="$(gh variable get ENCLAVE_GCS_MEDIA_BUCKET --repo "$REPOSITORY")"
EXPECTED_GCS_LEGACY_MEDIA_BUCKET="$(gh variable get ENCLAVE_GCS_LEGACY_MEDIA_BUCKET --repo "$REPOSITORY")"
ENCLAVE_RUN_SA_EMAIL="$(gh variable get ENCLAVE_RUN_SA_EMAIL --repo "$REPOSITORY")"
if [[ -z "$EXPECTED_GCS_BUCKET" || -z "$EXPECTED_GCS_MEDIA_BUCKET" || -z "$EXPECTED_GCS_LEGACY_MEDIA_BUCKET" || "$EXPECTED_GCS_LEGACY_MEDIA_BUCKET" != "$EXPECTED_GCS_BUCKET" ]]; then
  echo "Error: ENCLAVE_GCS_LEGACY_MEDIA_BUCKET must be configured and exactly match ENCLAVE_GCS_BUCKET for the Phase-0 dual-media migration." >&2
  exit 1
fi
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
if [[ "$ROLL" == "true" ]]; then
  apns_runtime_member="serviceAccount:${ENCLAVE_RUN_SA_EMAIL}"
  for apns_secret in kioku-apns-production-private-key kioku-apns-sandbox-private-key; do
    apns_latest_state="$(gcloud secrets versions describe latest \
      --secret "$apns_secret" \
      --project "$PROJECT_ID" \
      --format='value(state)' 2>/dev/null || true)"
    if [[ "$apns_latest_state" != "ENABLED" ]]; then
      echo "Error: required APNs secret has no enabled latest version: $apns_secret" >&2
      echo "       Refusing traffic promotion without reading or exposing the credential." >&2
      exit 1
    fi

    apns_policy="$(gcloud secrets get-iam-policy "$apns_secret" \
      --project "$PROJECT_ID" \
      --format=json 2>/dev/null || true)"
    if ! python3 -c '
import json
import sys

expected_member = sys.argv[1]
try:
    policy = json.load(sys.stdin)
except (json.JSONDecodeError, TypeError):
    raise SystemExit(1)

matches = [
    binding
    for binding in policy.get("bindings", [])
    if binding.get("role") == "roles/secretmanager.secretAccessor"
    and expected_member in binding.get("members", [])
]
raise SystemExit(0 if matches else 1)
' "$apns_runtime_member" <<< "$apns_policy"; then
      echo "Error: APNs secret lacks exact enclave runtime accessor binding: $apns_secret" >&2
      echo "       Expected roles/secretmanager.secretAccessor for $apns_runtime_member." >&2
      exit 1
    fi
  done
fi

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
if [[ "$PACKAGE_RELEASE_TAG" != "v${PACKAGE_VERSION}" ]]; then
  echo "Error: Cargo package version ${PACKAGE_VERSION} does not match ${PACKAGE_RELEASE_TAG}." >&2
  exit 1
fi

verify_required_ci_success() {
  local commit="$1"
  local run_json run_id jobs_json

  if ! run_json="$(gh run list \
    --repo "$REPOSITORY" \
    --workflow build.yml \
    --commit "$commit" \
    --event push \
    --limit 100 \
    --json databaseId,headBranch,headSha,status,conclusion)"; then
    echo "Error: could not query required CI for exact commit ${commit}." >&2
    return 1
  fi
  run_id="$(printf '%s' "$run_json" | python3 -c '
import json
import sys

expected_commit = sys.argv[1]
runs = json.load(sys.stdin)
matching = [
    run
    for run in runs
    if type(run) is dict
    and type(run.get("databaseId")) is int
    and run.get("headBranch") == "main"
    and run.get("headSha") == expected_commit
    and run.get("status") == "completed"
    and run.get("conclusion") == "success"
]
if not matching:
    raise SystemExit(
        "no successful completed push workflow run for the exact main commit"
    )
print(max(run["databaseId"] for run in matching))
' "$commit")" || {
    echo "Error: required CI has not succeeded for exact commit ${commit}." >&2
    echo "       Wait for the main push workflow to complete successfully, then retry." >&2
    return 1
  }

  if ! jobs_json="$(gh run view "$run_id" --repo "$REPOSITORY" --json jobs)"; then
    echo "Error: could not inspect required CI run ${run_id}." >&2
    return 1
  fi
  if ! printf '%s' "$jobs_json" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
jobs = data.get("jobs") if type(data) is dict else None
ci_jobs = [
    job
    for job in jobs or []
    if type(job) is dict and job.get("name") == "CI"
]
if len(ci_jobs) != 1:
    raise SystemExit("the exact workflow run did not contain exactly one CI job")
job = ci_jobs[0]
if job.get("status") != "completed" or job.get("conclusion") != "success":
    raise SystemExit("the required CI job did not complete successfully")
'; then
    echo "Error: required CI job did not succeed for exact commit ${commit}." >&2
    return 1
  fi

  echo "Verified required CI run ${run_id} for exact commit ${commit}."
}

if [[ "$ROLLBACK_EXISTING" == "false" ]]; then
  REQUIRED_CI_COMMIT="$COMMIT"
  if [[ "$RESUME_EXISTING" == "true" ]]; then
    REQUIRED_CI_COMMIT="$REMOTE_TAG_COMMIT"
  fi
  echo "Verifying required CI..."
  verify_required_ci_success "$REQUIRED_CI_COMMIT"
fi

if [[ "$ROLLBACK_EXISTING" == "false" && "$RESUME_EXISTING" == "false" ]]; then
  echo "Checking release-only metadata..."
  VOICE_QUALITY_GATE="$(python3 scripts/check_voice_release_gate.py)"
  EXPECTED_VOICE_QUALITY_GATE="$VOICE_QUALITY_GATE"
  EXPECTED_BILLING_ENFORCEMENT_MODE="$(gh variable get BILLING_ENFORCEMENT_MODE --repo "$REPOSITORY")"
  if [[ "$EXPECTED_BILLING_ENFORCEMENT_MODE" != "shadow" && "$EXPECTED_BILLING_ENFORCEMENT_MODE" != "enforce" ]]; then
    echo "Error: BILLING_ENFORCEMENT_MODE must be either shadow or enforce." >&2
    exit 1
  fi
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
METADATA_PROVENANCE_FILE="$WORK_DIR/enclave-release-metadata-provenance.jsonl"
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

if [[ ! -s "$METADATA_FILE" || ! -s "$METADATA_PROVENANCE_FILE" ]]; then
  echo "Error: build did not produce the signed enclave release metadata manifest and provenance bundle" >&2
  exit 1
fi

echo "Verifying signed release metadata manifest..."
gh attestation verify "$METADATA_FILE" \
  --repo "$REPOSITORY" \
  --bundle "$METADATA_PROVENANCE_FILE" \
  --deny-self-hosted-runners \
  --signer-workflow "${REPOSITORY}/.github/workflows/build.yml" \
  --source-digest "$REMOTE_TAG_COMMIT" \
  --source-ref "refs/tags/${RELEASE_TAG}" >/dev/null

RELEASE_METADATA="$(python3 scripts/verify_release_metadata.py \
  "$METADATA_FILE" \
  --repository "$REPOSITORY" \
  --tag "$RELEASE_TAG" \
  --commit "$REMOTE_TAG_COMMIT" \
  --image-repository "${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPOSITORY}/${IMAGE_NAME}" \
  --expected-gcs-bucket "$EXPECTED_GCS_BUCKET" \
  --expected-gcs-media-bucket "$EXPECTED_GCS_MEDIA_BUCKET" \
  --expected-gcs-legacy-media-bucket "$EXPECTED_GCS_LEGACY_MEDIA_BUCKET")"
# The verifier emits exact JSON because the signed manifest intentionally has
# consecutive empty exact-off claims. Extract only fields consumed below; each
# is verifier-required and nonempty. ASCII unit separator is non-whitespace and
# cannot occur because metadata validation rejects every control character.
RELEASE_METADATA_FIELDS="$(printf '%s' "$RELEASE_METADATA" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
keys = (
    "schema_version", "source_repository", "source_ref", "source_commit",
    "image_uri", "image_digest_uri", "image_digest", "build_url",
    "build_profile", "voice_quality_gate", "billing_enforcement_mode",
    "gcs_bucket", "gcs_media_bucket", "gcs_legacy_media_bucket",
)
print("\x1f".join(str(data[key]) for key in keys))
')"
IFS=$'\x1f' read -r SCHEMA_VERSION SOURCE_REPOSITORY BUILT_REF BUILT_COMMIT IMAGE_URI DIGEST_URI DIGEST BUILD_URL BUILD_PROFILE VOICE_QUALITY_GATE BILLING_ENFORCEMENT_MODE GCS_BUCKET GCS_MEDIA_BUCKET GCS_LEGACY_MEDIA_BUCKET <<< "$RELEASE_METADATA_FIELDS"

if [[ -n "$EXPECTED_VOICE_QUALITY_GATE" && "$VOICE_QUALITY_GATE" != "$EXPECTED_VOICE_QUALITY_GATE" ]]; then
  echo "Error: build metadata voice-quality classification does not match the checked source." >&2
  exit 1
fi
if [[ -n "$EXPECTED_BILLING_ENFORCEMENT_MODE" && "$BILLING_ENFORCEMENT_MODE" != "$EXPECTED_BILLING_ENFORCEMENT_MODE" ]]; then
  echo "Error: build metadata billing-enforcement mode does not match the checked repository configuration." >&2
  exit 1
fi
EXPECTED_IMAGE_REPOSITORY="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPOSITORY}/${IMAGE_NAME}"
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
  "| Voice quality gate | \`${VOICE_QUALITY_GATE}\` |" \
  "| Phase-0 current media bucket | \`${GCS_MEDIA_BUCKET}\` |" \
  "| Phase-0 legacy media bucket | \`${GCS_LEGACY_MEDIA_BUCKET}\` (must equal index \`${GCS_BUCKET}\`) |" \
  "" \
  "The digest is the attestation anchor used by the deployment's KMS policy." \
  "See README.md for the trust boundary and current reproducibility caveats." \
  > "$NOTES_FILE"

RELEASE_ASSETS=(
  "$METADATA_FILE"
  "$METADATA_PROVENANCE_FILE"
  "$PROVENANCE_FILE"
  "$SBOM_FILE"
  "$SBOM_ATTESTATION_FILE"
)
EXPECTED_ASSET_NAMES="$(printf '%s\n' \
  enclave-provenance.jsonl \
  enclave-release.json \
  enclave-release-metadata-provenance.jsonl \
  enclave-sbom-attestation.jsonl \
  enclave-sbom.spdx.json | sort)"
EXPECTED_ASSETS_CSV="$(tr '\n' ',' <<< "$EXPECTED_ASSET_NAMES" | sed 's/,$//')"
EXPECTED_PRERELEASE=false
PRERELEASE_ARGS=(--prerelease=false)
if [[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  EXPECTED_PRERELEASE=true
  PRERELEASE_ARGS=(--prerelease)
fi

# Another fingerprint-authorized operator invocation may publish while this
# script is waiting for and verifying build evidence. Refresh immediately
# before the first release mutation so a stale "missing" observation cannot
# lead to an unsafe create attempt. Existing immutable assets are never modified.
refresh_release_state_before_mutation() {
  local release_json release_state
  RELEASE_EXISTS=false
  RELEASE_IS_DRAFT=false
  RELEASE_IS_IMMUTABLE=false
  RELEASE_IS_PRERELEASE=false
  RELEASE_PUBLISHED_AT=""
  RELEASE_ASSETS_CSV=""

  if ! release_json="$(gh release view "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --json isDraft,isImmutable,isPrerelease,publishedAt,assets 2>/dev/null)"; then
    return 0
  fi
  if ! release_state="$(printf '%s' "$release_json" | python3 -c '
from datetime import datetime
import json, re, sys
release = json.load(sys.stdin)
for key in ("isDraft", "isImmutable", "isPrerelease"):
    if type(release.get(key)) is not bool:
        raise SystemExit("release state has a malformed boolean")
published_at = release.get("publishedAt")
if published_at is not None and not isinstance(published_at, str):
    raise SystemExit("release state has a malformed publication time")
if published_at:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})", published_at):
        raise SystemExit("release state has a malformed publication time")
    normalized_published_at = published_at[:-1] + "+00:00" if published_at.endswith("Z") else published_at
    try:
        parsed_published_at = datetime.fromisoformat(normalized_published_at)
    except ValueError as error:
        raise SystemExit("release state has a malformed publication time") from error
    if parsed_published_at.utcoffset() is None:
        raise SystemExit("release state has a malformed publication time")
assets = release.get("assets")
if not isinstance(assets, list) or any(not isinstance(asset, dict) or not isinstance(asset.get("name"), str) for asset in assets):
    raise SystemExit("release state has malformed assets")
names = [asset["name"] for asset in assets]
if len(names) != len(set(names)) or any("\t" in name or "\n" in name or "\r" in name for name in names):
    raise SystemExit("release state has unsafe asset names")
print("\t".join((str(release["isDraft"]).lower(), str(release["isImmutable"]).lower(), str(release["isPrerelease"]).lower(), published_at or "", ",".join(sorted(names)))))
')"; then
    echo "Error: release state is malformed; refusing to mutate the release." >&2
    exit 1
  fi
  IFS=$'\t' read -r RELEASE_IS_DRAFT RELEASE_IS_IMMUTABLE RELEASE_IS_PRERELEASE RELEASE_PUBLISHED_AT RELEASE_ASSETS_CSV <<< "$release_state"
  RELEASE_EXISTS=true
}

reverify_published_immutable_release() {
  local release_assets_dir asset_name
  if [[ "$RELEASE_IS_DRAFT" != "false" || "$RELEASE_IS_IMMUTABLE" != "true" || "$RELEASE_IS_PRERELEASE" != "$EXPECTED_PRERELEASE" || -z "$RELEASE_PUBLISHED_AT" ]]; then
    echo "Error: refreshed release is not a published immutable release matching the requested tag." >&2
    exit 1
  fi
  if [[ "$RELEASE_ASSETS_CSV" != "$EXPECTED_ASSETS_CSV" ]]; then
    echo "Error: refreshed immutable release does not contain exactly the expected assets." >&2
    exit 1
  fi
  release_assets_dir="$WORK_DIR/refreshed-immutable-release"
  mkdir -p "$release_assets_dir"
  for asset_name in $EXPECTED_ASSET_NAMES; do
    gh release download "$RELEASE_TAG" \
      --repo "$REPOSITORY" \
      --pattern "$asset_name" \
      --dir "$release_assets_dir"
    if ! cmp -s "$WORK_DIR/$asset_name" "$release_assets_dir/$asset_name"; then
      echo "Error: refreshed immutable release asset does not match verified build evidence: $asset_name" >&2
      exit 1
    fi
  done
}

create_release_or_reverify_publication_race() {
  if gh release create "$RELEASE_TAG" "${RELEASE_ASSETS[@]}" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --title "Kioku enclave $RELEASE_TAG" \
    --notes-file "$NOTES_FILE" \
    "${PRERELEASE_ARGS[@]}"; then
    return 0
  fi

  # Close the remaining check/create race as well as the longer evidence-wait
  # race above. A failed create may mean another authorized invocation
  # published first (or that the create response was lost). Only an exact
  # immutable release is accepted; an absent or draft release remains an
  # incomplete operation for a later explicit resume.
  echo "Release create did not complete; checking for concurrent authorized publication..."
  refresh_release_state_before_mutation
  if [[ "$RELEASE_EXISTS" == "true" && "$RELEASE_IS_DRAFT" == "false" ]]; then
    reverify_published_immutable_release
    return 0
  fi
  echo "Error: release create failed without an exact published immutable release." >&2
  return 1
}

refresh_release_state_before_mutation
if [[ "$RELEASE_EXISTS" == "true" && "$RELEASE_IS_DRAFT" == "false" ]]; then
  # This includes the publication race: only a complete immutable public
  # release may replace the planned create path, and it is re-verified before
  # proceeding without any edit or upload.
  reverify_published_immutable_release
fi

if [[ "$RELEASE_EXISTS" == "false" ]]; then
  # gh creates a draft internally, uploads every asset, and only then publishes;
  # this is required because immutable releases lock assets at publication.
  create_release_or_reverify_publication_race
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
  echo "Dispatching the explicitly confirmed production roll in $DEPLOYMENT_REPO..."
  gh workflow run enclave.yml \
    --repo "$DEPLOYMENT_REPO" \
    --ref main \
    -f "release_tag=$RELEASE_TAG" \
    -f "enclave_image=$DIGEST_URI" \
    -f "enclave_image_digest=$DIGEST" \
    -f "confirm=deploy"
  echo "Confirmed roll requested. Monitor it at:"
  echo "https://github.com/${DEPLOYMENT_REPO}/actions/workflows/enclave.yml"
else
  echo "Production was not changed. To request an explicitly confirmed roll:"
  echo "  $0 $RELEASE_TAG --roll"
fi
