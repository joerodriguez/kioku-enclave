#!/bin/sh
# Assemble the final image's allowlisted configuration from a BuildKit secret.
# This file is intentionally boring: it never sources/evaluates the input and
# never prints a value. Full semantic validation happens before Docker in the
# typed selector; this stage repeats the structural checks at the trust boundary.
set -eu

input=${1:?missing secret input}
output=${2:?missing output}
expected_sha256=${3:?missing CONFIG_SHA256}
case "$expected_sha256" in
  ''|*[!0-9a-f]*) exit 1 ;;
esac
test "${#expected_sha256}" -eq 64
test -f "$input"
test ! -L "$input"
input_sha256=$(sha256sum "$input" | awk '{print $1}')
test "$input_sha256" = "$expected_sha256"
umask 077
tmp="${output}.tmp"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
test ! -e "$tmp"
test ! -L "$tmp"
(set -C; : > "$tmp")

allowed_keys='KIOKU_BUILD_PROFILE KMS_PROJECT KMS_LOCATION KMS_KEY_RING KMS_KEY GCS_MEDIA_BUCKET RUN_SA_EMAIL ENCLAVE_AUDIENCE ATTEST_STS_AUDIENCE GOOGLE_DESKTOP_CLIENT_ID GOOGLE_IOS_CLIENT_ID GOOGLE_WEB_CLIENT_ID APPLE_TEAM_ID APPLE_KEY_ID APPLE_IOS_CLIENT_ID APPLE_MACOS_CLIENT_ID APPLE_WEB_CLIENT_ID APNS_TEAM_ID APNS_PRODUCTION_KEY_ID APNS_SANDBOX_KEY_ID ADMIN_USER_IDS SIGNUP_LIMIT_PER_DAY BASE_URL WEB_ORIGIN BILLING_SERVICE_URL BILLING_SERVICE_AUDIENCE BILLING_ENFORCEMENT_MODE REVIEWER_AUTH_API_KEY REVIEWER_AUTH_UID REVIEWER_AUTH_EMAIL VERTEX_PROJECT VERTEX_LOCATION VERTEX_MODEL POSTGRES_MAX_CONNECTIONS HEALTH_PORT DRAIN_TIMEOUT_SECONDS ENCLAVE_TLS'
allowed=" $allowed_keys "
seen=' '
while IFS='=' read -r name value || test -n "$name"; do
  case "$name" in
    ''|*[!A-Z0-9_]*|[0-9]*) exit 1 ;;
  esac
  case "$allowed" in *" $name "*) ;; *) exit 1 ;; esac
  case "$seen" in *" $name "*) exit 1 ;; esac
  case "$value" in *[![:print:]]*) exit 1 ;; esac
  printf '%s=%s\n' "$name" "$value" >> "$tmp"
  seen="$seen$name "
done < "$input"

for required in $allowed_keys; do
  case "$seen" in *" $required "*) ;; *) exit 1 ;; esac
done

# Recheck the high-impact image invariants after parsing, without evaluating
# the file as shell. The selector performs the complete grammar validation;
# these checks ensure a hand-authored secret cannot silently weaken the image.
value() { sed -n "s/^$1=//p" "$tmp"; }
profile=$(value KIOKU_BUILD_PROFILE)
test "$profile" = production || test "$profile" = evaluation
for required in KMS_PROJECT KMS_LOCATION KMS_KEY_RING KMS_KEY GCS_MEDIA_BUCKET \
  RUN_SA_EMAIL ENCLAVE_AUDIENCE ATTEST_STS_AUDIENCE \
  GOOGLE_DESKTOP_CLIENT_ID GOOGLE_IOS_CLIENT_ID GOOGLE_WEB_CLIENT_ID \
  ADMIN_USER_IDS SIGNUP_LIMIT_PER_DAY BASE_URL WEB_ORIGIN BILLING_SERVICE_URL BILLING_SERVICE_AUDIENCE \
  BILLING_ENFORCEMENT_MODE REVIEWER_AUTH_API_KEY REVIEWER_AUTH_UID REVIEWER_AUTH_EMAIL \
  VERTEX_PROJECT VERTEX_LOCATION VERTEX_MODEL; do
  test -n "$(value "$required")"
done
test "$(value POSTGRES_MAX_CONNECTIONS)" = 12
test "$(value HEALTH_PORT)" = 8081
test "$(value DRAIN_TIMEOUT_SECONDS)" = 105
test "$(value ENCLAVE_TLS)" = 1
case "$(value ADMIN_USER_IDS)" in *[!0-9A-Fa-f,-]*|'') exit 1 ;; esac
# Non-negative decimal, no leading zero. Zero closes signup; it is never read
# as unlimited. Empty, signed, and ambiguous leading-zero values still refuse.
case "$(value SIGNUP_LIMIT_PER_DAY)" in ''|*[!0-9]*|0[0-9]*) exit 1 ;; esac
case "$(value RUN_SA_EMAIL)" in *@*.iam.gserviceaccount.com) ;; *) exit 1 ;; esac
case "$(value ENCLAVE_AUDIENCE)" in https://*) ;; *) exit 1 ;; esac
case "$(value ATTEST_STS_AUDIENCE)" in //iam.googleapis.com/*/workloadIdentityPools/*/providers/*) ;; *) exit 1 ;; esac
case "$(value BASE_URL)" in https://*) ;; *) exit 1 ;; esac
case "$(value WEB_ORIGIN)" in https://*) ;; *) exit 1 ;; esac
case "$(value BILLING_SERVICE_URL)" in https://*) ;; *) exit 1 ;; esac
audience=$(value BILLING_SERVICE_AUDIENCE)
service_url=$(value BILLING_SERVICE_URL)
test "${audience%/}" = "${service_url%/}"
case "$(value BILLING_ENFORCEMENT_MODE)" in shadow|enforce) ;; *) exit 1 ;; esac
vertex_model=$(value VERTEX_MODEL)
case "$vertex_model" in *[!A-Za-z0-9._:-]*|'') exit 1 ;; esac
test "${#vertex_model}" -le 128
apple_values="$(value APPLE_TEAM_ID)$(value APPLE_KEY_ID)$(value APPLE_IOS_CLIENT_ID)$(value APPLE_MACOS_CLIENT_ID)$(value APPLE_WEB_CLIENT_ID)"
if test -n "$apple_values"; then
  test -n "$(value APPLE_TEAM_ID)" && test -n "$(value APPLE_KEY_ID)"
  test "$(value APPLE_IOS_CLIENT_ID)" = com.kioku.ios
  test "$(value APPLE_MACOS_CLIENT_ID)" = com.kiokuu.app
  test "$(value APPLE_WEB_CLIENT_ID)" = com.kiokuu.web
fi
if test "$profile" = production; then
  test -n "$(value APNS_TEAM_ID)" && test -n "$(value APNS_PRODUCTION_KEY_ID)" && test -n "$(value APNS_SANDBOX_KEY_ID)"
else
  apns_values="$(value APNS_TEAM_ID)$(value APNS_PRODUCTION_KEY_ID)$(value APNS_SANDBOX_KEY_ID)"
  if test -n "$apns_values"; then
    test -n "$(value APNS_TEAM_ID)" && test -n "$(value APNS_PRODUCTION_KEY_ID)" && test -n "$(value APNS_SANDBOX_KEY_ID)"
  fi
fi

test ! -e "$output"
test ! -L "$output"
output_sha256=$(sha256sum "$tmp" | awk '{print $1}')
test "$output_sha256" = "$expected_sha256"
ln "$tmp" "$output"
rm -f "$tmp"
test -f "$output"
test ! -L "$output"
test "$(sha256sum "$output" | awk '{print $1}')" = "$expected_sha256"
trap - EXIT HUP INT TERM
