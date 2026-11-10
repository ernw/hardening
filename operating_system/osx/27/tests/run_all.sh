#!/bin/bash
# Runs the test stages on a macOS 27 Mac and bundles the results.
#
#   probe     read-only evidence for the guide's commands and VERIFY-27 items
#   audit     hardener audit at baseline, high, and with optional checks
#   discover  interactive: you toggle settings, the script records what changed
#   fix       hardener audit -> fix -> audit -> rollback -> audit (changes the system)
#
# Usage: ./run_all.sh [--hardener <binary>] [--stages probe,audit] [--fix-level baseline]

set -u
. "$(dirname "$0")/lib.sh"

HARDENER=""
STAGES="probe,audit"
FIX_LEVEL="baseline"

while [ $# -gt 0 ]; do
  case "$1" in
    --hardener)  HARDENER="$2"; shift 2 ;;
    --stages)    STAGES="$2"; shift 2 ;;
    --fix-level) FIX_LEVEL="$2"; shift 2 ;;
    -h|--help)   sed -n '2,10p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

has_stage() { case ",$STAGES," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

require_macos27
if has_stage audit || has_stage fix; then
  [ -x "$HARDENER" ] || die "--hardener <binary> is required for the audit and fix stages"
  HARDENER="$(cd "$(dirname "$HARDENER")" && pwd)/$(basename "$HARDENER")"
fi

TS="$(date +%Y%m%d-%H%M%S)"
OUT="$TESTS_DIR/results/$TS"
mkdir -p "$OUT"
exec > >(tee -a "$OUT/run.log") 2>&1

{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "macos: $(sw_vers -productVersion) $(sw_vers -buildVersion)"
  echo "model: $(sysctl -n hw.model)"
  echo "stages: $STAGES"
  echo "fix_level: $FIX_LEVEL"
  echo "guide_commit: $(git -C "$GUIDE_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "guide_uncommitted_files: $(git -C "$GUIDE_DIR" status --porcelain -- . 2>/dev/null | wc -l | tr -d ' ')"
  [ -n "$HARDENER" ] && echo "hardener_sha256: $(shasum -a 256 "$HARDENER" | cut -d' ' -f1)"
} > "$OUT/meta.txt"
log "macOS $(sw_vers -productVersion), stages: $STAGES, results: $OUT"

sudo_keepalive

# hardener only knows baseline/medium/high and never runs "optional" checks.
ALL_RULESET="$OUT/ruleset-all.yaml"
sed 's/^\(  security_level: \)optional$/\1high/' "$RULESET" > "$ALL_RULESET"

# hardener writes reports/ and runs.json to the current directory.
hardener() {
  local dir="$1"; shift
  mkdir -p "$dir"
  ( cd "$dir" && "$HARDENER" "$@" < /dev/null )
}

summarize() {
  ls "$1"/reports/*.json >/dev/null 2>&1 || { warn "no reports in $1"; return; }
  osascript -l JavaScript "$TESTS_DIR/summarize.js" "$1"/reports/*.json | tee "$1/summary.txt"
}

if has_stage probe; then
  log "=== probe"
  "$TESTS_DIR/probe.sh" "$OUT/probe"
fi

if has_stage audit; then
  log "=== audit"
  hardener "$OUT/audit-baseline" audit --ruleset "$RULESET" --all --security-level baseline
  hardener "$OUT/audit-high"     audit --ruleset "$RULESET" --all --security-level high
  hardener "$OUT/audit-all"      audit --ruleset "$ALL_RULESET" --all --security-level high
  for d in audit-baseline audit-high audit-all; do summarize "$OUT/$d"; done
fi

if has_stage discover; then
  log "=== discover"
  "$TESTS_DIR/discover.sh" "$OUT/discover" < /dev/tty
fi

if has_stage fix; then
  log "=== fix ($FIX_LEVEL): changes the system configuration"
  printf 'Type "yes" to apply the %s fixes to this Mac: ' "$FIX_LEVEL"
  read -r confirm < /dev/tty
  if [ "$confirm" = "yes" ]; then
    d="$OUT/fix-cycle"
    hardener "$d" audit    --ruleset "$RULESET" --all --security-level "$FIX_LEVEL"
    hardener "$d" fix      --ruleset "$RULESET" --all --security-level "$FIX_LEVEL"
    hardener "$d" audit    --ruleset "$RULESET" --all --security-level "$FIX_LEVEL"
    hardener "$d" rollback --latest
    hardener "$d" audit    --ruleset "$RULESET" --all --security-level "$FIX_LEVEL"
    summarize "$d"
  else
    log "fix stage skipped"
  fi
fi

# runs.json holds full pre-fix copies of system files (e.g. sudoers).
BUNDLE="$TESTS_DIR/results/macos27-results-$TS.tar.gz"
tar -czf "$BUNDLE" -C "$TESTS_DIR/results" --exclude runs.json "$TS"
log "Bundle: $BUNDLE (contains this Mac's configuration, review before sharing)"
