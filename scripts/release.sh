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
LOCAL_ROLL_SCRIPT="scripts/local-operations.sh"
RELEASE_SIGNER_FINGERPRINT="${RELEASE_SIGNER_FINGERPRINT:-}"
EVIDENCE_PUBLIC_KEY="${LOCAL_BUILD_EVIDENCE_PUBLIC_KEY:-}"
EVIDENCE_PUBLIC_KEY_SHA256="${LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256:-}"
FROZEN_COMMIT=""
COORDINATOR_RECEIPT=""
COORDINATOR_SIGNATURE=""
COORDINATOR_PUBLIC_KEY="${COORDINATOR_ADVANCEMENT_PUBLIC_KEY:-}"
COORDINATOR_PUBLIC_KEY_SHA256="${COORDINATOR_ADVANCEMENT_PUBLIC_KEY_SHA256:-}"
PUSH_DEPLOYMENT_SOURCE_SEAL=""
ADR0022_FRESH_BOOTSTRAP_TAG="v0.8.35-adr0022-fresh-bootstrap.1"

usage() {
  cat <<'EOF'
Usage: scripts/release.sh <vMAJOR.MINOR.PATCH> --evidence-dir DIR --config FILE --repository OWNER/REPO [options]

Verifies a locally created and Ed25519-signed build evidence bundle, then plans
an immutable GitHub Release. No remote state changes occur without --apply.

Options:
  --apply                     Push the already-signed tag and publish the release.
  --roll                      After publication, invoke the local deployment roll script.
  --deployment-repo PATH      Checked-out Kioku deployment repository (required by --roll).
  --frozen-commit SHA          Build a detached frozen commit approved by a signed coordinator receipt.
  --coordinator-advancement-receipt PATH
                              Signed receipt for --frozen-commit (not a skip/force flag).
  --coordinator-advancement-signature PATH
                              Detached Ed25519 signature (default: receipt path + .sig).

Required environment:
  RELEASE_SIGNER_FINGERPRINT              trusted signed-tag key fingerprint
  LOCAL_BUILD_EVIDENCE_PUBLIC_KEY         external Ed25519 PEM public key path
  LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256  SHA-256 of that public key's DER form
  COORDINATOR_ADVANCEMENT_PUBLIC_KEY      external Ed25519 coordinator-key path (frozen mode)
  COORDINATOR_ADVANCEMENT_PUBLIC_KEY_SHA256 SHA-256 of that coordinator key's DER form
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
    --frozen-commit) FROZEN_COMMIT="${2:-}"; shift 2 ;;
    --coordinator-advancement-receipt) COORDINATOR_RECEIPT="${2:-}"; shift 2 ;;
    --coordinator-advancement-signature) COORDINATOR_SIGNATURE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; die "unknown option: $1" ;;
  esac
done

[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]] || die "release tag must look like v1.2.3 or v1.2.3-rc.1"
if [[ "$TAG" =~ [Aa][Dd][Rr]0022-[Ff][Rr][Ee][Ss][Hh]-[Bb][Oo][Oo][Tt][Ss][Tt][Rr][Aa][Pp] && "$TAG" != "$ADR0022_FRESH_BOOTSTRAP_TAG" ]]; then
  die "ADR-0022 fresh BOOTSTRAP tag must be exactly $ADR0022_FRESH_BOOTSTRAP_TAG"
fi
[[ "$REPOSITORY" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "--repository must be OWNER/REPO"
[[ -n "$EVIDENCE_DIR" && -d "$EVIDENCE_DIR" ]] || die "--evidence-dir must name an existing directory"
[[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]] || die "--config must name the local build configuration used for this image"
[[ -n "$RELEASE_SIGNER_FINGERPRINT" ]] || die "RELEASE_SIGNER_FINGERPRINT is required"
[[ -n "$EVIDENCE_PUBLIC_KEY" && -f "$EVIDENCE_PUBLIC_KEY" ]] || die "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY must name the external trust-anchor public key"
[[ "$EVIDENCE_PUBLIC_KEY_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "LOCAL_BUILD_EVIDENCE_PUBLIC_KEY_SHA256 must be a lowercase SHA-256 fingerprint"
[[ -z "${GOOGLE_APPLICATION_CREDENTIALS:-}" ]] || die "GOOGLE_APPLICATION_CREDENTIALS is not accepted; use reviewed gcloud identity configuration"
if [[ "$ROLL" == true && "$APPLY" != true ]]; then
  die "--roll requires --apply; review the dry-run output before allowing a VM replacement"
fi
if [[ "$ROLL" == true && ( -z "$DEPLOYMENT_REPO_PATH" || ! -d "$DEPLOYMENT_REPO_PATH" ) ]]; then
  die "--roll requires --deployment-repo pointing at a checked-out local deployment repository"
fi

for command_name in git gh python3 openssl; do need "$command_name"; done
cd "$REPO_ROOT"
if [[ -z "$FROZEN_COMMIT" ]]; then
  [[ "$(git branch --show-current)" == main ]] || die "releases must be prepared from local main"
else
  [[ "$FROZEN_COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "--frozen-commit must be a lowercase 40-character commit"
  [[ -n "$COORDINATOR_RECEIPT" && -f "$COORDINATOR_RECEIPT" ]] || die "--frozen-commit requires a signed coordinator advancement receipt"
  [[ -n "$COORDINATOR_PUBLIC_KEY" && -f "$COORDINATOR_PUBLIC_KEY" ]] || die "COORDINATOR_ADVANCEMENT_PUBLIC_KEY must name the coordinator trust anchor"
  [[ "$COORDINATOR_PUBLIC_KEY_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "COORDINATOR_ADVANCEMENT_PUBLIC_KEY_SHA256 must be a lowercase SHA-256 fingerprint"
  if [[ -z "$COORDINATOR_SIGNATURE" ]]; then
    COORDINATOR_SIGNATURE="${COORDINATOR_RECEIPT}.sig"
  fi
  [[ -f "$COORDINATOR_SIGNATURE" ]] || die "coordinator advancement signature is missing"
fi
[[ -z "$(git status --porcelain)" ]] || die "working tree is not clean"

# Read the exact local configuration through the same no-shell, ownership- and
# schema-checked parser used for image builds.  Only non-secret release claims
# cross this boundary.
RELEASE_CONFIG_SNAPSHOT="$(mktemp)"
chmod 600 "$RELEASE_CONFIG_SNAPSHOT"
trap 'rm -f "$RELEASE_CONFIG_SNAPSHOT"' EXIT
RELEASE_CONFIG_FIELDS="$(python3 - "$CONFIG_FILE" "$TAG" "$RELEASE_CONFIG_SNAPSHOT" <<'PY'
import sys
import os
from pathlib import Path
sys.path.insert(0, "scripts")
from local_image_pipeline import configured_environment_snapshot

configuration, builder, snapshot = configured_environment_snapshot(Path(sys.argv[1]), "production", sys.argv[2])
descriptor = os.open(sys.argv[3], os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
try:
    os.write(descriptor, snapshot.data)
finally:
    os.close(descriptor)
os.chmod(sys.argv[3], 0o600)
keys = (
    "PROJECT_ID", "REGION", "AR_REPOSITORY", "IMAGE_NAME",
    "ENCLAVE_GCS_BUCKET", "ENCLAVE_GCS_MEDIA_BUCKET",
    "ENCLAVE_GCS_LEGACY_MEDIA_BUCKET", "BILLING_ENFORCEMENT_MODE",
    "ARCHIVE_V3_SHADOW_RUNTIME_MODE", "GENESIS_WAL_NATIVE",
)
print("\x1f".join((*[configuration[key] for key in keys], builder)))
PY
)" || die "local release configuration is invalid"
CONFIG_FILE="$RELEASE_CONFIG_SNAPSHOT"
IFS=$'\x1f' read -r PROJECT_ID REGION AR_REPOSITORY IMAGE_NAME EXPECTED_GCS_BUCKET EXPECTED_GCS_MEDIA_BUCKET EXPECTED_GCS_LEGACY_MEDIA_BUCKET EXPECTED_BILLING_ENFORCEMENT_MODE ARCHIVE_V3_SHADOW_RUNTIME_MODE GENESIS_WAL_NATIVE BUILDER_SERVICE_ACCOUNT <<< "$RELEASE_CONFIG_FIELDS"
[[ -n "$PROJECT_ID" && -n "$REGION" && -n "$AR_REPOSITORY" && -n "$IMAGE_NAME" && -n "$BUILDER_SERVICE_ACCOUNT" ]] || die "local release configuration is incomplete"
if [[ "$ROLL" == true && "$TAG" == "$ADR0022_FRESH_BOOTSTRAP_TAG" ]]; then
  [[ "$ARCHIVE_V3_SHADOW_RUNTIME_MODE" == off && "$GENESIS_WAL_NATIVE" == off ]] \
    || die "fresh BOOTSTRAP roll requires archive runtime and Genesis exact off"
  [[ "${KIOKU_CONFIRM_ADR0022_FRESH_BOOTSTRAP_ROLL:-}" == "$TAG" ]] \
    || die "fresh BOOTSTRAP cannot roll without KIOKU_CONFIRM_ADR0022_FRESH_BOOTSTRAP_ROLL naming the exact tag"
elif [[ "$ROLL" == true && "$ARCHIVE_V3_SHADOW_RUNTIME_MODE" != off ]]; then
  # Deployment compatibility for active archive-v3 images (docs/adr/
  # 0022-solo-operator-activation.md): the baked runtime coordinates are consumed
  # by the pre-serving --run-archive-v3-phase1-canary subcommand and, since the
  # J-b3b serving-activation slice, by serving startup's WAL serving-authority
  # relaunch — an active-config image relaunches WAL authorities for every
  # durable-terminal user before any listener binds, and an off-config image
  # with such users refuses startup. Rolling an active-config image is therefore
  # a real behavioral decision and stays two-factor: the tag must be an exact
  # archive-v3 WAL release tag and the operator must acknowledge that exact tag
  # out of band.
  [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-archive-v3-wal\.[0-9]+$ ]] \
    || die "active archive-v3 WAL images cannot roll: tag is not an exact archive-v3-wal release tag"
  [[ "${KIOKU_CONFIRM_ARCHIVE_V3_ROLL:-}" == "$TAG" ]] \
    || die "active archive-v3 WAL images cannot roll without KIOKU_CONFIRM_ARCHIVE_V3_ROLL naming the exact tag"
fi

if [[ "$ROLL" == true ]]; then
  # APNs pacing and circuit state are process-local. Production therefore
  # supports push only from the exact reviewed deployment commit and complete
  # Terraform root-source seal. Discard the caller's path after one strict
  # realpath check so neither a symlinked ancestor nor an escaping/symlinked
  # rollout script can redirect the final invocation. Bind the source and exact
  # tracked executable before origin refresh, publication, registry access, or
  # rollout mutation; the same token is recomputed at the final boundary below.
  DEPLOYMENT_REPO_PATH="$(
    python3 scripts/verify_push_runtime_topology.py --canonical-path \
      "$DEPLOYMENT_REPO_PATH"
  )" || die "deployment repository path must be canonical and symlink-free"
  PUSH_DEPLOYMENT_SOURCE_SEAL="$(
    python3 scripts/verify_push_runtime_topology.py "$DEPLOYMENT_REPO_PATH"
  )" || die "push-capable rollout requires the reviewed single-runtime deployment source"
  [[ -n "$PUSH_DEPLOYMENT_SOURCE_SEAL" ]] \
    || die "push deployment source verifier returned no seal"
fi

# Keep the active-image rollout quarantine entirely local. It runs before the
# origin refresh so an ineligible roll performs no network or external action.
git fetch origin main
ORIGIN_MAIN="$(git rev-parse origin/main)"
if [[ -z "$FROZEN_COMMIT" ]]; then
  COMMIT="$(git rev-parse HEAD)"
  [[ "$COMMIT" == "$ORIGIN_MAIN" ]] || die "local main must exactly match origin/main"
else
  COMMIT="$FROZEN_COMMIT"
  [[ "$(git rev-parse HEAD)" == "$COMMIT" ]] || die "detached frozen mode requires HEAD to equal --frozen-commit"
  git cat-file -e "${COMMIT}^{commit}" || die "frozen commit is not present locally"
  git merge-base --is-ancestor "$COMMIT" "$ORIGIN_MAIN" || die "frozen commit is not an ancestor of fetched origin/main"
  python3 scripts/verify_coordinator_advancement_receipt.py \
    --receipt "$COORDINATOR_RECEIPT" \
    --signature "$COORDINATOR_SIGNATURE" \
    --public-key "$COORDINATOR_PUBLIC_KEY" \
    --expected-public-key-sha256 "$COORDINATOR_PUBLIC_KEY_SHA256" \
    --repository "$REPOSITORY" --tag "$TAG" \
    --frozen-commit "$COMMIT" --origin-main "$ORIGIN_MAIN" \
    >/dev/null || die "coordinator advancement receipt is invalid"
fi
IMAGE_REPOSITORY="${REGION}-docker.pkg.dev/${PROJECT_ID}/${AR_REPOSITORY}/${IMAGE_NAME}"

MANIFEST="$EVIDENCE_DIR/enclave-local-build-evidence.json"
SIGNATURE="$EVIDENCE_DIR/enclave-local-build-evidence.sig"
METADATA="$EVIDENCE_DIR/enclave-release.json"
SBOM="$EVIDENCE_DIR/enclave-sbom.spdx.json"
SCAN="$EVIDENCE_DIR/enclave-scan.json"
SOURCE_ARCHIVE="$(mktemp)"
trap 'rm -f "$SOURCE_ARCHIVE" "$RELEASE_CONFIG_SNAPSHOT"' EXIT
git archive --format=tar --output="$SOURCE_ARCHIVE" "$COMMIT" || die "could not materialize the immutable frozen source archive"
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
  --config "$CONFIG_FILE" \
  --source-archive "$SOURCE_ARCHIVE")"
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
)" || die "signed release metadata does not match the checked source/configuration"
[[ "$METADATA_CHECKS" == ok ]] || die "signed release metadata check did not complete"

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
trap 'rm -f "$NOTES" "$SOURCE_ARCHIVE" "$RELEASE_CONFIG_SNAPSHOT"' EXIT
printf '%s\n' \
  "Open-source Kioku enclave release **${TAG}**." "" \
  "| Field | Value |" "|---|---|" \
  "| Source commit | \`${COMMIT}\` |" \
  "| Image | \`${DIGEST_URI}\` |" \
  "| Image digest | \`${DIGEST}\` |" \
  "| Build evidence | locally built and signed with the configured external Ed25519 trust anchor |" \
  "| SBOM | \`${SBOM_VERSION}\` |" "" \
  "The digest is the deployment and KMS attestation anchor." > "$NOTES"

compare_existing_release_assets() {
  local downloaded asset
  downloaded="$(mktemp -d)"
  chmod 700 "$downloaded"
  for asset in "${EXPECTED_ASSETS[@]}"; do
    gh release download "$TAG" --repo "$REPOSITORY" --pattern "$asset" --dir "$downloaded" >/dev/null
    [[ -f "$downloaded/$asset" && ! -L "$downloaded/$asset" ]] || {
      rm -rf "$downloaded"
      die "published release asset is missing: $asset"
    }
    cmp -s "$EVIDENCE_DIR/$asset" "$downloaded/$asset" || {
      rm -rf "$downloaded"
      die "published release asset differs from local evidence: $asset"
    }
  done
  rm -rf "$downloaded"
}

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

RELEASE_STATE_ERROR="$(mktemp)"
trap 'rm -f "$RELEASE_STATE_ERROR" "$NOTES" "$SOURCE_ARCHIVE" "$RELEASE_CONFIG_SNAPSHOT"' EXIT
if ! release_json="$(gh release view "$TAG" --repo "$REPOSITORY" --json isDraft,isImmutable,isPrerelease,assets 2>"$RELEASE_STATE_ERROR")"; then
  release_error="$(<"$RELEASE_STATE_ERROR")"
  # gh has no machine-readable not-found exit code. Accept only its exact
  # documented absence messages; permission, transport, and malformed-state
  # failures must never be treated as an absent release.
  if [[ "$release_error" != "release not found" && "$release_error" != "HTTP 404: Not Found" ]]; then
    rm -f "$RELEASE_STATE_ERROR"
    die "could not read existing GitHub release state"
  fi
  release_json=""
fi
rm -f "$RELEASE_STATE_ERROR"
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
  compare_existing_release_assets
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
  compare_existing_release_assets
  fi

if [[ "$ROLL" == true ]]; then
  ROLL_PATH="${DEPLOYMENT_REPO_PATH}/${LOCAL_ROLL_SCRIPT}"
  [[ -f "$ROLL_PATH" && -x "$ROLL_PATH" ]] || die "configured local roll script is not executable: $ROLL_PATH"
  FINAL_PUSH_DEPLOYMENT_SOURCE_SEAL="$(
    python3 scripts/verify_push_runtime_topology.py "$DEPLOYMENT_REPO_PATH"
  )" || die "push deployment source changed before rollout"
  [[ "$FINAL_PUSH_DEPLOYMENT_SOURCE_SEAL" == "$PUSH_DEPLOYMENT_SOURCE_SEAL" ]] \
    || die "push deployment source seal changed after release preflight"
  KIOKU_PUSH_RUNTIME_SOURCE_SEAL="$PUSH_DEPLOYMENT_SOURCE_SEAL" \
    "$ROLL_PATH" enclave-roll --release-tag "$TAG" --image-uri "$DIGEST_URI" --digest "$DIGEST" --confirm "ROLL ENCLAVE $DIGEST" --apply
fi

echo "Published ${TAG} for ${DIGEST_URI}."
