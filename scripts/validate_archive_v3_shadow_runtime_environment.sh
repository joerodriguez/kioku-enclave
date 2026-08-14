#!/bin/sh
# Independent Docker build-argument validation for the inactive sealed runtime.
# Keep this grammar exactly aligned with archive_v3_shadow_runtime_config.py and
# ArchiveV3ShadowRuntimeDeployment::new.

set -eu
export LC_ALL=C

[ "$#" -eq 8 ] || exit 2

mode=$1
archive_bucket=$2
archive_project_number=$3
registry_kms_version=$4
witness_project_id=$5
witness_project_number=$6
witness_database_id=$7
archive_binding_commitment=$8

has_control_character() {
    without_controls=$(printf '%sX' "$1" | tr -d '[:cntrl:]')
    [ "$without_controls" != "${1}X" ]
}

canonical_u64() {
    value=$1
    case "$value" in
        ''|0|0*|*[!0-9]*) return 1 ;;
    esac
    length=${#value}
    [ "$length" -lt 20 ] && return 0
    [ "$length" -eq 20 ] || return 1
    first=$(printf '%s\n%s\n' "$value" 18446744073709551615 | sort | sed -n '1p')
    [ "$first" = "$value" ]
}

valid_ipv4_address() {
    value=$1
    old_ifs=$IFS
    IFS=.
    set -- $value
    IFS=$old_ifs
    [ "$#" -eq 4 ] || return 1
    for component in "$@"; do
        case "$component" in
            0|[1-9]|[1-9][0-9]|[1-9][0-9][0-9]) ;;
            *) return 1 ;;
        esac
        [ "$component" -le 255 ] || return 1
    done
}

valid_bucket() {
    value=$1
    length=${#value}
    [ "$length" -ge 3 ] || return 1
    printf '%s\n' "$value" | grep -Eq '^[a-z0-9][a-z0-9._-]*[a-z0-9]$' || return 1
    case "$value" in
        goog*|*google*|*g00gle*) return 1 ;;
    esac
    case "$value" in
        *.*)
            [ "$length" -le 222 ] || return 1
            old_ifs=$IFS
            IFS=.
            set -- $value
            IFS=$old_ifs
            for component in "$@"; do
                [ -n "$component" ] && [ "${#component}" -le 63 ] || return 1
            done
            ;;
        *) [ "$length" -le 63 ] || return 1 ;;
    esac
    ! valid_ipv4_address "$value"
}

for value in "$@"; do
    ! has_control_character "$value" || exit 1
done

case "$mode" in
    off)
        [ -z "${archive_bucket}${archive_project_number}${registry_kms_version}${witness_project_id}${witness_project_number}${witness_database_id}${archive_binding_commitment}" ]
        ;;
    single-archive-wal-v1)
        valid_bucket "$archive_bucket"
        canonical_u64 "$archive_project_number"
        canonical_u64 "$registry_kms_version"
        printf '%s\n' "$witness_project_id" | grep -Eq '^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
        canonical_u64 "$witness_project_number"
        printf '%s\n' "$witness_database_id" | grep -Eq '^[a-z][a-z0-9-]{2,61}[a-z0-9]$'
        if printf '%s\n' "$witness_database_id" | grep -Eq '^[0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12}$'; then
            exit 1
        fi
        printf '%s\n' "$archive_binding_commitment" | grep -Eq '^[0-9a-f]{64}$'
        [ "$archive_binding_commitment" != "0000000000000000000000000000000000000000000000000000000000000000" ]
        ;;
    *) exit 1 ;;
esac
