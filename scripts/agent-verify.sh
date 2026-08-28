#!/usr/bin/env bash
# Lightweight, locked local verification for the enclave worktree.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MIN_FREE_GIB="${AGENT_VERIFY_MIN_FREE_GIB:-15}"
SCCACHE_CACHE_SIZE="${AGENT_VERIFY_SCCACHE_CACHE_SIZE:-10G}"

usage() {
  cat <<'EOF'
Usage: ./scripts/agent-verify.sh [quick|focused|full] [-- <cargo test arguments...>]

Modes:
  quick                 Check formatting and compile with `cargo check` (default).
  focused -- <filter> [args...]
                         Check formatting and run a focused `cargo test` selection.
  full                  Check formatting, run the full test suite against a real
                        PostgreSQL database, and run all-target Clippy.

All Cargo commands use --locked. `focused` requires a non-option test filter so it
cannot accidentally expand into the full suite. The disk preflight requires 15 GiB of
free space by default; set AGENT_VERIFY_MIN_FREE_GIB to a positive integer to adjust it.
If sccache is installed, it is enabled with a bounded 10G cache by default; set
AGENT_VERIFY_SCCACHE_CACHE_SIZE to a whole number of GiB from 1G through 10G to adjust it.
When the cache daemon starts, it receives every live linked-worktree root so
otherwise-identical compiler inputs can be reused across their absolute paths.
Verification exits instead of waiting when this worktree's build-artifact lock is held.
Full mode requires KIOKU_TEST_POSTGRES_URL to name an already-provisioned disposable
PostgreSQL database. It never starts Docker implicitly. The release owner is responsible
for provisioning PostgreSQL 17 and destroying it after verification.
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 2
}

if [[ ! "$MIN_FREE_GIB" =~ ^[1-9][0-9]*$ ]]; then
  fail "AGENT_VERIFY_MIN_FREE_GIB must be a positive whole number of GiB."
fi

configure_sccache() {
  local basedirs_match cache_size_gib current_max_bytes requested_max_bytes
  local sccache_basedirs sccache_path stats_summary
  sccache_path="$(command -v sccache 2>/dev/null || true)"
  if [[ ! -x "$sccache_path" ]]; then
    return
  fi

  # Do not replace a caller-selected wrapper; sccache is an optional accelerator.
  if [[ -n "${RUSTC_WRAPPER:-}" ]]; then
    echo "Leaving caller-provided RUSTC_WRAPPER unchanged."
    return
  fi

  if [[ ! "$SCCACHE_CACHE_SIZE" =~ ^([1-9]|10)G$ ]]; then
    fail "AGENT_VERIFY_SCCACHE_CACHE_SIZE must be between 1G and 10G."
  fi

  if ! sccache_basedirs="$(git worktree list --porcelain -z | python3 -c '
import os
import sys

current = os.path.realpath(sys.argv[1])
roots = {current}
for field in sys.stdin.buffer.read().split(b"\0"):
    if not field.startswith(b"worktree "):
        continue
    path = os.fsdecode(field.removeprefix(b"worktree "))
    if os.path.isdir(path):
        roots.add(os.path.realpath(path))
if any(os.pathsep in root for root in roots):
    raise SystemExit("a worktree path contains the sccache basedir separator")
print(os.pathsep.join(sorted(roots)))
' "$REPO_ROOT")" || [[ -z "$sccache_basedirs" ]]; then
    echo "Could not derive safe worktree paths for sccache; continuing without it." >&2
    return
  fi

  export RUSTC_WRAPPER="$sccache_path"
  export SCCACHE_CACHE_SIZE
  # A freshly started daemon receives every live linked-worktree root, allowing
  # identical compiler inputs to reuse objects despite different absolute paths.
  export SCCACHE_BASEDIRS="$sccache_basedirs"
  cache_size_gib="${SCCACHE_CACHE_SIZE%G}"
  requested_max_bytes=$((cache_size_gib * 1024 * 1024 * 1024))
  if ! "$sccache_path" --start-server >/dev/null 2>&1; then
    echo "Installed sccache could not start safely; continuing without it." >&2
    unset RUSTC_WRAPPER SCCACHE_BASEDIRS SCCACHE_CACHE_SIZE
    return
  fi
  if ! stats_summary="$("$sccache_path" --show-stats --stats-format json \
    | python3 -c '
import json
import os
import sys

data = json.load(sys.stdin)
maximum = data.get("max_cache_size")
actual = data.get("basedirs")
if type(maximum) is not int or type(actual) is not list or not all(type(path) is str for path in actual):
    raise SystemExit("sccache did not report its effective bounds")
requested = {os.path.realpath(path) for path in sys.argv[1].split(os.pathsep)}
configured = {os.path.realpath(path) for path in actual}
print(maximum)
print("yes" if requested.issubset(configured) else "no")
' "$sccache_basedirs")"; then
    echo "Installed sccache could not prove its cache settings; continuing without it." >&2
    unset RUSTC_WRAPPER SCCACHE_BASEDIRS SCCACHE_CACHE_SIZE
    return
  fi
  current_max_bytes="${stats_summary%%$'\n'*}"
  basedirs_match="${stats_summary#*$'\n'}"
  if [[ ! "$current_max_bytes" =~ ^[0-9]+$ || "$basedirs_match" != "yes" ]]; then
    echo "Installed sccache server does not cover these worktrees; continuing without it." >&2
    unset RUSTC_WRAPPER SCCACHE_BASEDIRS SCCACHE_CACHE_SIZE
    return
  fi
  # Server-scoped settings can predate this invocation. Never claim a bound
  # that an already-running sccache server is not actually enforcing.
  if (( current_max_bytes > requested_max_bytes )); then
    echo "Installed sccache server exceeds ${SCCACHE_CACHE_SIZE}; continuing without it." >&2
    unset RUSTC_WRAPPER SCCACHE_BASEDIRS SCCACHE_CACHE_SIZE
    return
  fi
  echo "Using installed sccache with cache limit at most ${SCCACHE_CACHE_SIZE}."
}

mode="quick"
if [[ $# -gt 0 ]]; then
  case "$1" in
    quick|focused|full)
      mode="$1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      fail "unknown mode: $1"
      ;;
  esac
fi

case "$mode" in
  quick|full)
    if [[ $# -ne 0 ]]; then
      usage >&2
      fail "$mode does not accept additional arguments."
    fi
    ;;
  focused)
    if [[ "${1:-}" != "--" ]]; then
      usage >&2
      fail "focused requires -- followed by one or more cargo test arguments."
    fi
    shift
    if [[ $# -eq 0 ]]; then
      usage >&2
      fail "focused requires at least one cargo test argument."
    fi
    if [[ "$1" == -* ]]; then
      usage >&2
      fail "focused requires a non-option test filter before any cargo test arguments."
    fi
    ;;
esac

if [[ "$mode" == full ]]; then
  postgres_url="${KIOKU_TEST_POSTGRES_URL:-}"
  [[ -n "$postgres_url" ]] || fail \
    "full verification requires KIOKU_TEST_POSTGRES_URL; provision disposable PostgreSQL 17 explicitly."
  case "$postgres_url" in
    postgres://*|postgresql://*) ;;
    *) fail "KIOKU_TEST_POSTGRES_URL must use the postgres or postgresql URL scheme." ;;
  esac
  [[ "$postgres_url" != *$'\n'* && "$postgres_url" != *$'\r'* ]] || \
    fail "KIOKU_TEST_POSTGRES_URL contains a control character."
  # The Rust contract harness treats this as a no-skip assertion. Keeping the
  # signal separate from the credential makes accidental environment loss
  # visible instead of reporting a false-green release gate.
  export KIOKU_REQUIRE_POSTGRES_CONTRACT=1
fi

cd "$REPO_ROOT"
python3 "$SCRIPT_DIR/check_build_disk_space.py" --path "$REPO_ROOT" --min-free-gib "$MIN_FREE_GIB"
configure_sccache

# The helper holds one crash-safe kernel lock across the entire Cargo sequence.
# Positional arguments keep focused test filters intact without string evaluation.
python3 "$SCRIPT_DIR/rust_build_lock.py" --worktree "$REPO_ROOT" -- \
  "$BASH" -c '
    set -euo pipefail
    mode="$1"
    shift
    case "$mode" in
      quick)
        cargo fmt --all -- --check
        cargo check --locked
        ;;
      focused)
        cargo fmt --all -- --check
        cargo test --locked "$@"
        ;;
      full)
        cargo fmt --all -- --check
        cargo test --locked
        cargo clippy --locked --all-targets -- -D warnings
        ;;
    esac
  ' agent-verify-locked "$mode" "$@"
