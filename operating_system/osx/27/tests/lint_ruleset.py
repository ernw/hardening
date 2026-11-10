#!/usr/bin/env python3
"""Static checks for ruleset.yaml: structure, IDs, levels and shell syntax. Needs PyYAML."""
import re
import subprocess
import sys

import yaml

LEVELS = {"baseline", "medium", "high", "optional"}
REQUIRED = ["id", "description", "command", "expected", "security_level"]


def shell_error(snippet):
    if snippet.strip().lower().startswith("manual action required"):
        return None
    r = subprocess.run(["sh", "-n"], input=snippet, text=True, capture_output=True)
    return r.stderr.strip() if r.returncode else None


def lint(path):
    docs = [d for d in yaml.safe_load_all(open(path)) if d]
    errors, ids, count = [], set(), 0
    for suite in docs[1:]:
        title = suite.get("title", "<untitled>")
        if suite.get("os") != "darwin":
            errors.append(f"{title}: os must be darwin")
        if suite.get("arch") != ["arm64"]:
            errors.append(f"{title}: arch must be [arm64]")
        for c in suite.get("checksuites", []):
            count += 1
            cid = c.get("id", "<no id>")
            errors += [f"{cid}: missing {k}" for k in REQUIRED if k not in c]
            if cid in ids:
                errors.append(f"{cid}: duplicate id")
            ids.add(cid)
            if c.get("security_level") not in LEVELS:
                errors.append(f"{cid}: invalid security_level {c.get('security_level')!r}")
            if "arch" in c:
                errors.append(f"{cid}: check-level arch is ignored by hardener")
            cmd = str(c.get("command", ""))
            # hardener accepts grep's exit code 1 ("0 matches") only if the command contains "grep -c".
            if re.search(r"grep(\s+-[A-Za-z]+)*\s+-[A-Za-z]*c", cmd) and "grep -c" not in cmd:
                errors.append(f"{cid}: write counting greps as 'grep -c ...'")
            for field in ("command", "fix"):
                if field in c and (err := shell_error(str(c[field]))):
                    errors.append(f"{cid}: {field}: {err}")
    return count, len(docs) - 1, errors


if __name__ == "__main__":
    checks, suites, errors = lint(sys.argv[1])
    print(f"ruleset: {suites} suites, {checks} checks, {len(errors)} errors")
    for e in errors:
        print("  ERROR:", e)
    sys.exit(1 if errors else 0)
