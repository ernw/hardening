# Sourced by the test scripts. Must stay compatible with /bin/bash 3.2.

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUIDE_DIR="$(cd "$TESTS_DIR/.." && pwd)"
export RULESET="$GUIDE_DIR/ruleset.yaml"

log()  { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
warn() { printf '[%s] WARNING: %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# macOS has no coreutils timeout.
run_with_timeout() {
  local secs="$1"; shift
  "$@" &
  local pid=$!
  ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null ) &
  local watcher=$!
  wait "$pid" 2>/dev/null
  local rc=$?
  kill "$watcher" 2>/dev/null
  wait "$watcher" 2>/dev/null
  return $rc
}

sudo_keepalive() {
  sudo -v || die "sudo authentication failed"
  ( while kill -0 "$$" 2>/dev/null; do sudo -n true 2>/dev/null; sleep 50; done ) &
  SUDO_KEEPALIVE_PID=$!
  trap 'kill "$SUDO_KEEPALIVE_PID" 2>/dev/null' EXIT
}

require_macos27() {
  [ "$(uname -s)" = "Darwin" ] || die "must run on macOS"
  [ "$(uname -m)" = "arm64" ] || die "macOS 27 requires Apple Silicon"
  [ "$(id -u)" != "0" ] || die "run as your admin user, not via sudo (user-domain checks would read root's preferences)"
  local version
  version="$(sw_vers -productVersion)"
  case "$version" in
    27.*) ;;
    *) [ "${ALLOW_OTHER_VERSION:-0}" = "1" ] || die "expected macOS 27, found $version (ALLOW_OTHER_VERSION=1 runs anyway, as a smoke test)"
       warn "running on macOS $version: results are not evidence for macOS 27" ;;
  esac
}
