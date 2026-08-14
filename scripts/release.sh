#!/usr/bin/env bash
# Publish a locally built, locally signed Kioku enclave release.  GitHub is
# used only as the source/release host; no GitHub Actions workflow is invoked.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
APPLY=false
ROLL=false
TAG=""
EVIDENCE_DIR=""
CONFIG_FILE=""
REPOSITORY=""
DEPLOYMENT_REPO_PATH="${DEPLOYMENT_REPO_PATH:-}"
LOCAL_ROLL_SCRIPT="${LOCAL_ROLL_SCRIPT:-scripts/local-operations.sh}"
RELEASE_SIGNER_FINGERPRINT="${RELEASE_SIGNER_FINGERPRINT:-}"
EVIDENCE_PUBLIC_KEY="${LOCAL_BUILD_EVIDENCE_PUBLIC_KEY:-}"
EVIDENCE_PUBLIC_KEY_SHA256="${LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256:-}"

usage() {
  cat <<'EOF'
Usage: scripts/release.sh <vMAJOR.MINOR.PATCH> --evidence-dir DIR --config FILE --repository OWNER/REPO [options]

Verifies a locally created and Ed25519-signed build evidence bundle, then plans
an immutable GitHub Release. No remote state changes occur without --apply.

Options:
  --apply                     Push the already-signed tag and publish the release.
  --roll                      After publication, invoke the local deployment roll script.
  --deployment-repo PATH      Checked-out Kioku deployment repository (required by --roll).
  --roll-script PATH          Path relative to deployment repo (default scripts/local-operations.sh).

Required environment:
  RELEASE_SIGNER_FINGERPRINT              trusted signed-tag key fingerprint
  LOCAL_BUILD_EVIDENCE_PUBLIC_KEY         external Ed25519 PEM public key path
  LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256  SHA-256 of that public key's DER form
EOF
}

die() { echo "Error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

[[ $# -ge 1 ]] || { usage; exit 2; }
TAG="$1"
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --evidence-dir) EVIDENCE_DIR="${2:-}"; shift 2 ;;
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    --repository) REPOSITORY="${2:-}"; shift 2 ;;
    --apply) APPLY=true; shift ;;
    --roll) ROLL=true; shift ;;
    --deployment-repo) DEPLOYMENT_REPO_PATH="${2:-}"; shift 2 ;;
    --roll-script) LOCAL_ROLL_SCRIPT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
done

[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "release tag must look like v1.2.3 or v1.2.3-rc.1"
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repository must be OWNER/REPO"
[[ -n "$EVIDENCE_DIR" && -d "$EVIDENCE_DIR" ]] || die "--evidence-dir must name an existing directory"
[[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]] || die "--config must name the local build configuration used for this image"
[[ -n "$RELEASE_SIGNER_FINGERPRINT" ]] || die "RELEASE_SIGNER_FINGERPRINT is required"
[[ -n "$EVIDENCE_PUBLIC_KEY" && -f "$EVIDENCE_PUBLIC_KEY" ]] || die "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY must name the external trust-anchor public key"
[[ "$EVIDENCE_PUBLIC_KEY_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256 must be a lowercase SHA-256 fingerprint"
if [[ "$ROLL" == true && "$APPLY" != true ]]; then
  die "--roll requires --apply; review the dry-run output before allowing a VM replacement"
fi
if [[ "$ROLL" == true && ( -z "$DEPLOYMENT_REPO_PATH" || ! -d "$DEPLOYMENT_REPO_PATH" ) ]]; then
  die "--roll requires --deployment-repo pointing at a checked-out local deployment repository"
fi

for command_name in git gh python3 openssl; do need "$command_name"; done
cd "$REPO_ROOT"
[[ "$(git branch --show-current)" == main ]] || die "releases must be prepared from local main"
[[ -z "$(git status --porcelain)" ]] || die "working tree is not clean"

# Read the exact local configuration through the same no-shell, ownership- and
# schema-checked parser used for image builds.  Only non-secret release claims
# cross this boundary.
RELEASE_CONFIG_FIELDS="$(python3 - "$CONFIG_FILE" "$TAG" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, "scripts")
from local_image_pipeline import configured_environment

configuration, builder = configured_environment(Path(sys.argv[1]), "production", sys.argv[2])
keys = (
    "PROJECT_ID", "REGION", "AR_REPOSITORY", "IMAGE_NAME",
    "ENCLAVE_GCS_BUCKET", "ENCLAVE_GCS_MEDIA_BUCKET",
    "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET", "BILLING_ENFORCEMENT_MODE",
    "ARCHIVE_V3_SHADOW_RUNTIME_MODE",
)
print("\x1f".join((*[configuration[key] for key in keys], builder)))
PY
)" || die "local release configuration is invalid"
IFS=$'\x1f' read -r PROJECT_ID REGION AR_REPOSITORY IMAGE_NAME EXPECTED_GCS_BUCKET EXPECTED_GCS_MEDIA_BUCKET EXPECTED_GCS_LEGACY_MEDIA_BUCKET EXPECTED_BILLING_ENFORCEMENT_MODE ARCHIVE_V3_SHADOW_RUNTIME_MODE BUILDER_SERVICE_ACCOUNT <<< "$RELEASE_CONFIG_FIELDS"
[[ -n "$PROJECT_ID" && -n "$REGION" && -n "$AR_REPOSITORY" && -n "$IMAGE_NAME" && -n "$BUILDER_SERVICE_ACCOUNT" ]] || die "local release configuration is incomplete"
if [[ "$ROLL" == true && "$ARCHIVE_V3_SHADOW_RUNTIME_MODE" != off ]]; then
  die "active archive-v3 WAL images cannot roll until the deployment compatibility PR is merged"
fi

# Keep the active-image rollout quarantine entirely local. It runs before the
# origin refresh so an ineligible roll performs no network or external action.
git fetch origin main
COMMIT="$(git rev-parse HEAD)"
[[ "$COMMIT" == "$(git rev-parse origin/main)" ]] || die "local main must exactly match origin/main"
IMAGE_REPOSITORY="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPOSITORY}/${IMAGE_NAME}"

MANIFEST="$EVIDENCE_DIR/enclave-local-build-evidence.json"
SIGNATURE="$EVIDENCE_DIR/enclave-local-build-evidence.sig"
METADATA="$EVIDENCE_DIR/enclave-release.json"
SBOM="$EVIDENCE_DIR/enclave-sbom.spdx.json"
SCAN="$EVIDENCE_DIR/enclave-scan.json"
[[ -s "$MANIFEST" && -s "$SIGNATURE" && -s "$METADATA" && -s "$SBOM" && -s "$SCAN" ]] || die "evidence directory must contain the signed manifest, release metadata, SBOM, and scan result"

EVIDENCE_BUNDLE="$(python3 scripts/verify_local_evidence_bundle.py \
  --evidence-dir "$EVIDENCE_DIR" \
  --public-key "$EVIDENCE_PUBLIC_KEY" \
  --expected-public-key-sha256 "$EVIDENCE_PUBLIC_KEY_SHA256" \
  --repository "$REPOSITORY" --tag "$TAG" --commit "$COMMIT" \
  --image-repository "$IMAGE_REPOSITORY" \
  --expected-gcs-bucket "$EXPECTED_GCS_BUCKET" \
  --expected-gcs-media-bucket "$EXPECTED_GCS_MEDIA_BUCKET" \
  --expected-gcs-legacy-media-bucket "$EXPECTED_GCS_LEGACY_MEDIA_BUCKET" \
  --config "$CONFIG_FILE")"
EVIDENCE_FIELDS="$(EVIDENCE_BUNDLE="$EVIDENCE_BUNDLE" python3 - <<'PY'
import json
import os

bundle = json.loads(os.environ["EVIDENCE_BUNDLE"])
data = bundle["evidence"]
metadata = bundle["metadata"]
print("\x1f".join((data["source_ref"], data["source_commit"], data["image_digest_uri"], data["image_digest"], data["image_uri"], bundle["sbom_version"])))
PY
)"
IFS=$'\x1f' read -r EVIDENCE_TAG EVIDENCE_COMMIT DIGEST_URI DIGEST IMAGE_URI SBOM_VERSION <<< "$EVIDENCE_FIELDS"
[[ -n "$EVIDENCE_TAG" && -n "$EVIDENCE_COMMIT" && -n "$DIGEST_URI" && -n "$DIGEST" && -n "$IMAGE_URI" && "$SBOM_VERSION" == SPDX-* ]] || die "evidence parser returned incomplete data"
[[ "$EVIDENCE_TAG" == "$TAG" ]] || die "evidence source_ref does not match the requested tag"
[[ "$EVIDENCE_COMMIT" == "$COMMIT" ]] || die "evidence source_commit does not match local main"
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ && "$DIGEST_URI" == *@"$DIGEST" ]] || die "evidence image digest is malformed"
VOICE_QUALITY_GATE="$(python3 scripts/check_voice_release_gate.py)"
METADATA_CHECKS="$(EVIDENCE_BUNDLE="$EVIDENCE_BUNDLE" python3 - "$VOICE_QUALITY_GATE" "$EXPECTED_BILLING_ENFORCEMENT_MODE" <<'PY'
import json
import os
import sys
metadata = json.loads(os.environ["EVIDENCE_BUNDLE"])["metadata"]
if metadata["voice_quality_gate"] != sys.argv[1]:
    raise SystemExit("release metadata voice-quality classification differs from checked source")
if metadata["billing_enforcement_mode"] != sys.argv[2]:
    raise SystemExit("release metadata billing-enforcement mode differs from selected configuration")
print("ok")
PY
)" || die "schema-9 release metadata does not match the checked source/configuration"
[[ "$METADATA_CHECKS" == ok ]] || die "schema-9 release metadata check did not complete"

verify_tag_signer() {
  local verification fingerprints
  verification="$(git verify-tag --raw "$TAG" 2>&1)" || die "$TAG does not have a valid signed-tag signature"
  if [[ "$RELEASE_SIGNER_FINGERPRINT" == SHA256:* ]]; then
    fingerprints="$(printf '%s\n' "$verification" | sed -nE 's/^.* key (SHA256:[A-Za-z0-9+\/=]+).*$/\1/p')"
  else
    fingerprints="$(printf '%s\n' "$verification" | awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print toupper($3); if (NF >= 12) print toupper($NF) }')"
    RELEASE_SIGNER_FINGERPRINT="$(printf '%s' "$RELEASE_SIGNER_FINGERPRINT" | tr '[:lower:]' '[:upper:]')"
  fi
  grep -qxF "$RELEASE_SIGNER_FINGERPRINT" <<< "$fingerprints" || die "$TAG was not signed by RELEASE_SIGNER_FINGERPRINT"
}

git rev-parse -q --verify "refs/tags/$TAG" >/dev/null || die "create the signed local tag before building release evidence"
[[ "$(git rev-list -n 1 "$TAG")" == "$COMMIT" ]] || die "signed tag does not point at local main"
verify_tag_signer

EXPECTED_ASSETS=(enclave-local-build-evidence.json enclave-local-build-evidence.sig enclave-release.json enclave-sbom.spdx.json enclave-scan.json)
EXPECTED_PRERELEASE=true
if [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  EXPECTED_PRERELEASE=false
fi
NOTES="$(mktemp)"
trap 'rm -f "$NOTES"' EXIT
printf '%s\n' \
  "Open-source Kioku enclave release **${TAG}**." "" \
  "| Field | Value |" "|---|---|" \
  "| Source commit | \`${COMMIT}\` |" \
  "| Image | \`${DIGEST_URI}\` |" \
  "| Image digest | \`${DIGEST}\` |" \
  "| Build evidence | locally built and signed with the configured external Ed25519 trust anchor |" \
  "| SBOM | \`${SBOM_VERSION}\` |" "" \
  "The digest is the deployment and KMS attestation anchor." > "$NOTES"

echo "Local evidence is valid for ${TAG}: ${DIGEST_URI}"
if [[ "$APPLY" != true ]]; then
  echo "Dry run only. --apply would push the already-signed tag and create an immutable GitHub Release."
  [[ "$ROLL" == true ]] && echo "It would then invoke ${DEPLOYMENT_REPO_PATH}/${LOCAL_ROLL_SCRIPT} with the exact digest confirmation."
  exit 0
fi

need gcloud
IMMUTABLE_RELEASES_ENABLED="$(gh api -H 'X-GitHub-Api-Version: 2026-03-10' \
  "repos/${REPOSITORY}/immutable-releases" --jq .enabled)"
[[ "$IMMUTABLE_RELEASES_ENABLED" == true ]] || die "GitHub immutable releases must be enabled before publication"
REGISTRY_DIGEST="$(gcloud --impersonate-service-account="$BUILDER_SERVICE_ACCOUNT" \
  artifacts docker images describe "$DIGEST_URI" --format='value(image_summary.digest)')"
[[ "$REGISTRY_DIGEST" == "$DIGEST" ]] || die "Artifact Registry did not resolve the signed image digest"
git push origin "$TAG"

release_json="$(gh release view "$TAG" --repo "$REPOSITORY" --json isDraft,isImmutable,isPrerelease,assets 2>/dev/null || true)"
if [[ -n "$release_json" ]]; then
  RELEASE_JSON="$release_json" EXPECTED_PRERELEASE="$EXPECTED_PRERELEASE" python3 - "${EXPECTED_ASSETS[@]}" <<'PY'
import json
import os
import sys
release = json.loads(os.environ["RELEASE_JSON"])
expected = sorted(sys.argv[1:])
actual = sorted(asset.get("name") for asset in release.get("assets", []) if isinstance(asset, dict))
expected_prerelease = os.environ["EXPECTED_PRERELEASE"] == "true"
if release.get("isDraft") is not False or release.get("isImmutable") is not True or release.get("isPrerelease") is not expected_prerelease or actual != expected:
    raise SystemExit("existing release is not the expected immutable evidence release")
PY
  echo "Existing immutable release is already exact; it was not modified."
else
  if [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    gh release create "$TAG" "$MANIFEST" "$SIGNATURE" "$METADATA" "$SBOM" "$SCAN" \
      --repo "$REPOSITORY" --verify-tag --title "Kioku enclave $TAG" --notes-file "$NOTES"
  else
    gh release create "$TAG" "$MANIFEST" "$SIGNATURE" "$METADATA" "$SBOM" "$SCAN" \
      --repo "$REPOSITORY" --verify-tag --title "Kioku enclave $TAG" --notes-file "$NOTES" \
      --prerelease
  fi
  final="$(gh release view "$TAG" --repo "$REPOSITORY" --json isDraft,isImmutable,isPrerelease,assets)"
  RELEASE_JSON="$final" EXPECTED_PRERELEASE="$EXPECTED_PRERELEASE" python3 - "${EXPECTED_ASSETS[@]}" <<'PY'
import json
import os
import sys
release = json.loads(os.environ["RELEASE_JSON"])
expected = sorted(sys.argv[1:])
actual = sorted(asset.get("name") for asset in release.get("assets", []) if isinstance(asset, dict))
expected_prerelease = os.environ["EXPECTED_PRERELEASE"] == "true"
if release.get("isDraft") is not False or release.get("isImmutable") is not True or release.get("isPrerelease") is not expected_prerelease or actual != expected:
    raise SystemExit("GitHub did not publish the expected immutable evidence release")
PY
fi

if [[ "$ROLL" == true ]]; then
  ROLL_PATH="${DEPLOYMENT_REPO_PATH}/${LOCAL_ROLL_SCRIPT}"
  [[ -f "$ROLL_PATH" && -x "$ROLL_PATH" ]] || die "configured local roll script is not executable: $ROLL_PATH"
  "$ROLL_PATH" enclave-roll --release-tag "$TAG" --image-uri "$DIGEST_URI" --digest "$DIGEST" --confirm "ROLL ENCLAVE $DIGEST" --apply
fi

echo "Published ${TAG} for ${DIGEST_URI}."
