#!/bin/bash
# Offline checks for the guide, ruleset and test scripts. Runs on macOS or Linux.
# Needs python3 with PyYAML; uses shellcheck and node when available.

set -u
cd "$(dirname "$0")" || exit 1
GUIDE="$(ls ../Hardening_Guide-*.md)"
fail=0
step() { printf '\n== %s\n' "$1"; }

step "guide"
python3 lint_guide.py "$GUIDE" || fail=1

step "ruleset"
if python3 -c 'import yaml' 2>/dev/null; then
  python3 lint_ruleset.py ../ruleset.yaml || fail=1
else
  echo "PyYAML missing: python3 -m pip install --user pyyaml"; fail=1
fi

step "shell scripts"
for f in *.sh; do bash -n "$f" || fail=1; done
if command -v shellcheck >/dev/null; then
  shellcheck -s bash -S warning ./*.sh && echo "shellcheck: ok" || fail=1
else
  echo "shellcheck not installed, skipped"
fi

step "summarize.js"
cd fixtures || exit 1
if command -v osascript >/dev/null; then
  actual="$(osascript -l JavaScript ../summarize.js report-fix.json)"
elif command -v node >/dev/null; then
  actual="$(node -e '
    const fs = require("fs");
    global.ObjC = { import() {}, unwrap: x => x };
    global.$ = { NSUTF8StringEncoding: 4, NSString: { stringWithContentsOfFileEncodingError: p =>
      Object.assign(new String(fs.readFileSync(p, "utf8")), { isNil: () => false }) } };
    eval(fs.readFileSync("../summarize.js", "utf8"));
    console.log(run(["report-fix.json"]));')"
else
  actual=""; echo "neither osascript nor node available, skipped"
fi
if [ -n "$actual" ]; then
  if [ "$actual" = "$(cat report-fix.summary.txt)" ]; then echo "summary: ok"
  else echo "summary differs from fixtures/report-fix.summary.txt:"; diff <(echo "$actual") report-fix.summary.txt; fail=1; fi
fi

step "result"
[ "$fail" = 0 ] && echo "all checks passed" || echo "FAILED"
exit "$fail"
