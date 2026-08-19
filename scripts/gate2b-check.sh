#!/usr/bin/env bash
set -euo pipefail

# Gate 2b — silent test file drop detection.
#
# Extracted out of .github/workflows/test-baseline-guard.yml so this logic
# can be exercised (and proven) outside GitHub Actions. See
# scripts/gate2b-self-test.sh for the self-test that plants a divergence.
#
# INVARIANT: `expected_files` MUST be derived from the same `test.include`
# globs vitest.config.ts hands to vitest at runtime, never restated by hand
# in this script. A hand-restated root here is exactly the drift class that
# let a real silent-drop bug hide under a 14-file cushion: `expected_files`
# used to be `find server/test -name "*.test.ts" | wc -l`, which only scans
# one of vitest.config.ts's two `test.include` roots
# (`test/**/*.test.ts` and `../scripts/synthetic-coverage/test/**/*.test.ts`).
# On a real run that was 992 files on disk vs. 1006 loaded by vitest — up to
# 14 server/test files could be silently dropped and this gate would still
# report green, because the untracked second root's 14 files masked the
# gap. Fixed 2026-08-19 (pre-existing on main, independent of any open PR).
# MUST MATCH: `test.include` in server/vitest.config.ts (cross-file pin;
# server/scripts/count-vitest-test-files.mjs reads that array directly
# instead of copying it, so this file needs no matching edit when the
# include list changes).
#
# Usage: scripts/gate2b-check.sh <vitest-output-log>

usage() {
  echo "Usage: scripts/gate2b-check.sh <vitest-output-log>" >&2
}

if [[ $# -ne 1 ]]; then
  usage
  exit 2
fi

VITEST_LOG="$1"
# Self-locate rather than trusting cwd (git-independent on purpose: the
# self-test drives this script against a throwaway fixture directory that is
# not necessarily a git repo).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
COUNT_SCRIPT="$REPO_ROOT/server/scripts/count-vitest-test-files.mjs"

if [[ ! -f "$VITEST_LOG" ]]; then
  echo "::error::vitest output log not found at $VITEST_LOG" >&2
  exit 1
fi

if [[ ! -f "$COUNT_SCRIPT" ]]; then
  echo "::error::count script not found at $COUNT_SCRIPT" >&2
  exit 1
fi

expected_files=$(node "$COUNT_SCRIPT")
if ! [[ "$expected_files" =~ ^[0-9]+$ ]]; then
  echo "::error::count-vitest-test-files.mjs did not print an integer: '$expected_files'" >&2
  exit 1
fi

actual_total=$(grep -oE "Test Files[[:space:]]+.*\([0-9]+\)" "$VITEST_LOG" | grep -oE "\([0-9]+\)" | tr -d '()' | tail -1)
if [[ -z "$actual_total" ]]; then
  actual_total=$(grep -oE "Test Files[[:space:]]+[0-9]+ passed" "$VITEST_LOG" | grep -oE "[0-9]+" | head -1)
fi
if [[ -z "$actual_total" ]]; then
  echo "::error::Could not parse 'Test Files' count from vitest output." >&2
  tail -30 "$VITEST_LOG" >&2
  exit 1
fi

echo "Files matching vitest's test.include globs: $expected_files"
echo "Files vitest loaded:                        $actual_total"

# FAILURE MODE: this inequality (not exact equality) is intentional, not a
# leftover from the pre-fix shape. expected_files is a static glob match on
# disk; actual_total is vitest's own runtime "Test Files" reporter total. A
# future vitest version could in principle report a matched-but-fully-skipped
# file differently than "collected", so exact equality risks a false CI
# failure on a benign reporting nuance. What equality would buy over `<` is
# catching the *surplus* direction (actual_total > expected_files), which
# cannot represent a drop — it is logged below, not failed. The slack this
# leaves is bounded to zero in the common case, because both sides now come
# from the identical include globs; it is not bounded to zero by the type
# system, which is why this stays a runtime check.
if (( actual_total < expected_files )); then
  echo "::error::Silent test file drop detected: $expected_files files match vitest's test.include globs, $actual_total loaded by vitest. Missing $((expected_files - actual_total)) file(s). This is the exact failure class from commit 4ac95830 (see docs/audit/commit-4ac95830-postmortem.md)."
  exit 1
fi

if (( actual_total > expected_files )); then
  echo "Note: vitest loaded more files ($actual_total) than the include globs matched on disk ($expected_files). Not a drop (a drop is undercounting, not overcounting) — worth a look if unexpected, not failing this gate."
fi

echo "✓ All $expected_files test files loaded by vitest."
