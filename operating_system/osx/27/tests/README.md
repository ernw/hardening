# Tests: macOS 27 Golden Gate Hardening Guide

Two kinds of tests:

- **Offline checks** (`check.sh`), runnable on any machine: guide structure, ruleset structure, script syntax, report summarizer.
- **Device tests** (`run_all.sh`), on a macOS 27 Mac with Apple Silicon: collect evidence for the `VERIFY-27` markers and run the ruleset through [hardener](https://github.com/mev0lent/hardener).

## Offline Checks

```bash
python3 -m pip install --user pyyaml   # once
./check.sh
```

| Check | What it verifies |
|---|---|
| `lint_guide.py` | TOC matches the headings, internal links resolve, images exist and are used, footnotes are defined and used. `--fix-toc` regenerates the TOC. |
| `lint_ruleset.py` | Required fields, unique IDs, valid security levels, `arch: [arm64]`, `sh -n` on every command and fix, hardener-compatible `grep -c` usage. |
| shell scripts | `bash -n`, plus `shellcheck` if installed. |
| `summarize.js` | Output for `fixtures/report-fix.json` matches `fixtures/report-fix.summary.txt` (via `osascript`, or `node` elsewhere). |

## Device Tests

Run as an admin user, not via `sudo`. Build hardener first:

```bash
git clone https://github.com/mev0lent/hardener.git
cd hardener && GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o hardener-macos .
```

Then, from this directory:

```bash
./run_all.sh --hardener ~/hardener/hardener-macos                       # 1. probe + audit, read-only
./run_all.sh --stages discover                                         # 2. interactive settings discovery
./run_all.sh --hardener ~/hardener/hardener-macos --stages fix          # 3. fix cycle, changes the system
```

| Stage | Changes the system | What it does |
|---|---|---|
| `probe` | no | Runs the guide's compliance commands and the VERIFY-27 probes, records command, output and exit code in `probe/probe.txt`. |
| `audit` | no | hardener audit at `baseline`, `high`, and with `optional` checks raised to `high` (hardener never runs `optional`). |
| `discover` | only what you change | For each step, snapshots all preferences, asks you to change one setting in System Settings, snapshots again, and records the changed keys and files. Used to find where macOS 27 stores the new Siri AI, Writing Assistance and Background Security Improvements settings. |
| `fix` | **yes** | hardener audit, fix, audit, rollback, audit at `--fix-level` (default `baseline`). Asks for confirmation. |

Run `discover` before `fix`, so that the snapshots start from Apple's defaults. On another macOS version, `ALLOW_OTHER_VERSION=1` runs the suite as a smoke test of the scripts; the results are not evidence for macOS 27.

Results go to `results/<timestamp>/` and are bundled as `results/macos27-results-<timestamp>.tar.gz`. The bundle contains the Mac's configuration; review it before sharing. hardener's `runs.json` (pre-fix file copies) is excluded.

`summary.txt` in each hardener stage lists:

| State | Meaning |
|---|---|
| `error` | The check command failed. Usually a broken check, not a finding. Fix first. |
| `fix_not_effective` | The fix ran, the check still fails: wrong fix, wrong check, or a pending reboot. |
| `missing_command` | Required tool not installed (e.g. Homebrew). |
| `failed` | A finding. Expected on an unhardened Mac. |

## Closing VERIFY-27 Markers

1. Look up the marker's topic in `probe/probe.txt` (tags like `[powernap]`, `[diskimage]`, `[ssh]`, `[pqc]`, `[tcc]`).
2. Update the guide and remove the marker.
3. Fix every `error` and `fix_not_effective` check in `ruleset.yaml`.
4. Replace the manual Siri/Apple Intelligence checks with the keys found by `discover`.
5. Run `./check.sh`.
