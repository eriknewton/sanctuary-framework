#!/usr/bin/env bash
set -euo pipefail

# Gate 2b - silent test file drop detection.
#
# Extracted out of .github/workflows/test-baseline-guard.yml so this logic
# can be exercised (and proven) outside GitHub Actions. See
# scripts/gate2b-self-test.sh for the self-test that plants a divergence.
#
# INVARIANT: `expected_files` MUST come from vitest's OWN file discovery
# (server/scripts/count-vitest-test-files.mjs, which shells out to `vitest
# list --filesOnly`), never from a re-implementation of test.include/exclude/
# dot/root/projects resolution in this script or in that one. Round 1 of this
# gate (`find server/test -name "*.test.ts"`) only scanned one of
# vitest.config.ts's two `test.include` roots and let up to 14 dropped files
# pass undetected (992 on disk vs. 1006 loaded by vitest). Round 2 replaced
# the shell `find` with a hand-rolled glob over `test.include` in the count
# script - closer, but still a second implementation of vitest's resolution
# that had no idea about `test.exclude`, `dot`, `root`/`dir`, `includeSource`,
# or a workspace/projects config, any of which could silently diverge from
# what vitest actually runs. See the count script's header for round 2's fix:
# it now asks vitest for the list directly instead of modeling it, so there
# is nothing left in either file to keep in sync with vitest.config.ts.
#
# Usage: scripts/gate2b-check.sh <vitest-output-log>

usage() {
  echo "Usage: scripts/gate2b-check.sh <vitest-output-log>" >&2
}

# Mirrors .githooks/pre-commit's validate_counter: a vitest-derived counter is
# grep -oE "[0-9]+"-shaped but not yet SAFE to hand to `(( ))`. A leading-zero
# string (e.g. "007") risks an octal-parse surprise, and an absurdly long
# digit string can overflow bash's signed-64-bit arithmetic and silently
# wrap - on a wrapped-negative count, a "less than" comparison can invert.
# This is the single implementation both this script (CI, and via the hook
# below) and the local pre-commit hook now share for its own counters, so
# the two cannot drift on how strict this check is the way they drifted on
# whether expected_files=0 was acceptable (finding that motivated unifying
# this file in the first place).
COUNTER_MAX=100000000 # 9 digits; no real suite approaches 100M files/tests.
validate_counter() {
  local name="$1" value="$2"
  if ! [[ "$value" =~ ^(0|[1-9][0-9]*)$ ]]; then
    echo "::error::$name is not a canonical non-negative integer, got: '$value'" >&2
    exit 1
  fi
  if (( ${#value} > ${#COUNTER_MAX} )) \
     || { (( ${#value} == ${#COUNTER_MAX} )) && (( value > COUNTER_MAX )); }; then
    echo "::error::$name is implausibly large ('$value') - refusing to trust it." >&2
    exit 1
  fi
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
validate_counter "expected test file count" "$expected_files"
if (( expected_files == 0 )); then
  # FAILURE MODE: 0 is never a valid expected count, however cleanly the
  # arithmetic below might compare it. It means vitest's OWN discovery found
  # nothing to run - a bad vitest.config.ts, a wrong --root, or a moved test
  # directory - and letting 0 flow into "actual_total == expected_files"
  # would make the gate pass vacuously if the run also (wrongly) reports 0.
  echo "::error::vitest's own discovery (vitest list --filesOnly) found 0 test files. Refusing to treat 0 as a valid expected count - something is catastrophically wrong with vitest.config.ts or the invocation root." >&2
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
validate_counter "vitest-reported Test Files count" "$actual_total"

echo "Files vitest's own discovery finds: $expected_files"
echo "Files vitest loaded for the run:    $actual_total"

# FAILURE MODE: this is EXACT equality, not `actual_total < expected_files`.
# An earlier version of this gate tolerated actual_total > expected_files on
# the theory that expected_files was a static glob model that could
# legitimately undercount a runtime edge case. That reasoning no longer
# applies: expected_files now comes from `vitest list --filesOnly`, which
# calls vitest's OWN `getRelevantTestSpecifications` - the exact same method
# a real `vitest run` uses to decide what to run. Both numbers describe the
# identical set by construction, computed by vitest itself against the same
# checkout in the same CI job. There is no known legitimate case where they
# differ in EITHER direction: a shortfall is a drop (the class this gate
# exists to catch); a surplus would mean vitest ran a file its own discovery
# call didn't report, which is not a "less bad" story than a drop - it means
# the two vitest invocations disagreed with themselves, and that is exactly
# as untrustworthy. Do not reintroduce a `<`-only comparison or a tolerated
# surplus without first identifying a concrete, named case that makes them
# differ (see the review note against the original inequality version of
# this gate for why "a future vitest version might report a skipped file
# differently" was not such a case once both sides share one discovery call).
if (( actual_total != expected_files )); then
  if (( actual_total < expected_files )); then
    echo "::error::Silent test file drop detected: vitest's own discovery found $expected_files test file(s), but only $actual_total loaded for the run. Missing $((expected_files - actual_total)) file(s). This is the exact failure class from commit 4ac95830 (see docs/audit/commit-4ac95830-postmortem.md)."
  else
    echo "::error::Unexpected surplus: vitest loaded $actual_total file(s) for the run but its own discovery call only found $expected_files. Both numbers are supposed to come from the same vitest discovery mechanism against the same checkout - this means the two invocations disagreed, which is not a known-safe case. Investigate before assuming this is benign."
  fi
  exit 1
fi

echo "✓ All $expected_files test files loaded by vitest."
