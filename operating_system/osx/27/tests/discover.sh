#!/bin/bash
# Interactive. For each step: snapshot preferences, you change ONE setting in
# System Settings, snapshot again, record the diff and modified files.
# The script itself changes nothing. Usage: ./discover.sh <output-dir> [step ...]

set -u
. "$(dirname "$0")/lib.sh"

OUT="${1:?usage: $0 <output-dir> [step ...]}"; shift
SELECTED=" $* "
mkdir -p "$OUT"

STEPS=(
  "Screen Time > Content & Privacy: turn ON Content & Privacy"
  "Screen Time > Content & Privacy > Siri: select 'Don't Allow Siri'"
  "Screen Time > Content & Privacy > Siri: select 'Siri Classic'"
  "Screen Time > Content & Privacy > Siri: turn OFF Writing Assistance"
  "Screen Time > Content & Privacy > Siri: turn OFF Image Creation"
  "Siri: turn Siri OFF (System Settings > Siri)"
  "Privacy & Security > Background Security Improvements: change the installation setting"
  "Privacy & Security > Apple Intelligence Report: change the report duration"
  "Privacy & Security > Analytics & Improvements: turn OFF Share Mac Analytics"
  "General > Software Update > Automatic Updates (i): toggle 'Install Security Responses and system files'"
  "General > Software Update > Automatic Updates (i): toggle 'Install macOS updates'"
  "Notifications: turn OFF Summarize Notifications"
  "Finder > Settings: uncheck 'Suggest file names'"
  "General > AirDrop & Handoff: turn OFF AirPlay Receiver"
  "Privacy & Security > Accessories: change 'Allow accessories to connect'"
)

export_domains() {
  local flag="$1" dir="$2" d
  # shellcheck disable=SC2086 # $flag is empty or -currentHost
  defaults $flag domains | tr ',' '\n' | sed 's/^ *//' | while read -r d; do
    [ -n "$d" ] && defaults $flag export "$d" - 2>/dev/null | plutil -convert xml1 -o "$dir/$d.plist" - 2>/dev/null
  done
}

snapshot() {
  local dir="$1" f
  mkdir -p "$dir/user" "$dir/host" "$dir/system"
  export_domains "" "$dir/user"
  defaults export NSGlobalDomain - 2>/dev/null | plutil -convert xml1 -o "$dir/user/NSGlobalDomain.plist" - 2>/dev/null
  export_domains "-currentHost" "$dir/host"
  for f in /Library/Preferences/*.plist /Library/Managed\ Preferences/*.plist /Library/Managed\ Preferences/"$USER"/*.plist; do
    [ -f "$f" ] && sudo plutil -convert xml1 -o "$dir/system/$(basename "$f")" "$f" 2>/dev/null
  done
  sudo chown -R "$USER" "$dir" 2>/dev/null
}

changed_files() {
  find "$HOME/Library" -newer "$1" -type f -not -path '*/Caches/*' -not -path '*/Logs/*' -not -path '*/Saved Application State/*' 2>/dev/null
  sudo find /Library/Preferences /private/var/db -newer "$1" -type f -not -path '*/diagnostics/*' -not -path '*/uuidtext/*' 2>/dev/null
}

# Keep only the plists that changed: limits size and personal data in the bundle.
prune_unchanged() {
  local sdir="$1" side f rel
  for side in before after; do
    find "$sdir/$side" -type f | while read -r f; do
      rel="${f#"$sdir/$side/"}"
      cmp -s "$sdir/before/$rel" "$sdir/after/$rel" && rm -f "$f"
    done
  done
}

require_macos27
sudo_keepalive

i=0
for step in "${STEPS[@]}"; do
  i=$((i + 1))
  if [ "$SELECTED" != "  " ]; then
    case "$SELECTED" in *" $i "*) ;; *) continue ;; esac
  fi
  sdir="$OUT/step$(printf '%02d' "$i")"
  mkdir -p "$sdir"
  echo "$step" > "$sdir/step.txt"
  echo
  log "Step $i: $step"
  snapshot "$sdir/before"
  touch "$sdir/.marker"; sleep 1
  printf 'Change the setting now, then press Enter ("s" + Enter skips): '
  read -r answer
  if [ "$answer" = "s" ]; then echo "skipped" >> "$sdir/step.txt"; continue; fi
  sleep 3
  snapshot "$sdir/after"
  changed_files "$sdir/.marker" > "$sdir/changed_files.txt"
  diff -r "$sdir/before" "$sdir/after" > "$sdir/defaults.diff" 2>&1
  prune_unchanged "$sdir"
  log "changed plists: $(grep -c '^diff ' "$sdir/defaults.diff"), modified files: $(wc -l < "$sdir/changed_files.txt" | tr -d ' ')"
  printf 'Optional note on what exactly you changed (Enter to continue): '
  read -r note
  [ -n "$note" ] && echo "note: $note" >> "$sdir/step.txt"
done
log "Done: $OUT"
