#!/usr/bin/env bash
set -euo pipefail

# Self-test for scripts/gate2b-check.sh, which .githooks/pre-commit now
# calls directly instead of keeping its own copy of this logic.
#
# Four cases against throwaway fixtures whose vitest.config.ts has the same
# two-root include shape as server/vitest.config.ts:
#
#   1. No drop: the fixed check passes.
#   2. Planted drop (fabricated actual_total): the fixed check FAILS, and
#      the ROUND-1 formula (`find server/test` only, restated inline below
#      for comparison - the literal formula the original fix replaced)
#      PASSES on the exact same drop, reproducing the 992-vs-1006 /
#      14-file-cushion defect at a small scale.
#   3. Surplus (fabricated actual_total): now a hard failure, not a
#      tolerated informational note - proves equality is enforced.
#   4. A REAL `vitest run` plus a REAL `test.exclude` entry: proves the
#      counter's discovery side (not just the comparison logic) matches
#      vitest's own behavior on a config surface a hand-rolled glob would
#      miss, and reproduces the ROUND-2 formula (test.include globbed by
#      hand, no test.exclude support - the fix that preceded asking vitest
#      directly) FALSE-FAILING that same healthy run.
#
# Cases 1-3 fabricate actual_total to test the comparison logic in
# isolation and deterministically; case 4 drives both sides from vitest
# itself so the discovery side is proven against real vitest behavior, not
# just modeled. Mirrors the fixture-and-assert shape of
# scripts/verify-fail-before-self-test.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# All fixture dirs get cleaned up on ANY exit path (success, `fail`, or an
# unexpected error under `set -e`), not just the happy path - a case that
# calls `fail` exits immediately and would otherwise leak a mktemp dir per
# invocation.
CLEANUP_DIRS=()
cleanup() {
  local dir
  for dir in "${CLEANUP_DIRS[@]:-}"; do
    [[ -n "$dir" ]] && rm -rf "$dir"
  done
}
trap cleanup EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

write_file() {
  local root="$1" rel="$2" body="$3"
  local path="$root/$rel"
  mkdir -p "$(dirname "$path")"
  printf '%s' "$body" > "$path"
}

# Builds a fixture whose layout mirrors the real repo closely enough for
# count-vitest-test-files.mjs to behave identically: a server/ dir with its
# own vitest.config.ts + scripts/ (copied, not reimplemented, so the self-test
# exercises the SAME code the workflow and hook run) and a top-level
# scripts/synthetic-coverage/test/ dir as the second include root.
#
# node_modules is SYMLINKED from the real repo rather than installed, because
# count-vitest-test-files.mjs needs `vite` and `tinyglobby` resolvable via
# normal Node module resolution starting at its own directory, and installing
# a second copy for a throwaway fixture would be slow and pointless - the
# fixture only needs to exercise the glob-derivation logic, not a fresh
# dependency tree.
build_fixture() {
  local root="$1"
  local server_test_count="$2"   # files under server/test
  local synthetic_count="$3"     # files under scripts/synthetic-coverage/test

  mkdir -p "$root/server/scripts" "$root/scripts/synthetic-coverage/test" "$root/server/test"

  cp "$SCRIPT_DIR/gate2b-check.sh" "$root/scripts/gate2b-check.sh"
  chmod +x "$root/scripts/gate2b-check.sh"
  cp "$REPO_ROOT/server/scripts/count-vitest-test-files.mjs" "$root/server/scripts/count-vitest-test-files.mjs"
  ln -s "$REPO_ROOT/server/node_modules" "$root/server/node_modules"

  # "type": "module" mirrors server/package.json - without it, Vite's config
  # loader treats the .ts config as CommonJS and emits an unrelated migration
  # warning on stderr that has nothing to do with what this self-test proves.
  write_file "$root" "server/package.json" '{"type": "module"}
'
  write_file "$root" "server/vitest.config.ts" 'export default {
  test: {
    include: ["test/**/*.test.ts", "../scripts/synthetic-coverage/test/**/*.test.ts"],
  },
};
'

  for i in $(seq 1 "$server_test_count"); do
    write_file "$root" "server/test/fixture-$i.test.ts" "it('fixture $i', () => { expect(true).toBe(true); });\n"
  done
  for i in $(seq 1 "$synthetic_count"); do
    write_file "$root" "scripts/synthetic-coverage/test/fixture-$i.test.ts" "it('synthetic fixture $i', () => { expect(true).toBe(true); });\n"
  done
}

# Reproduces the EXACT pre-fix formula this change replaced (see the removed
# lines in .github/workflows/test-baseline-guard.yml and .githooks/pre-commit
# in this same PR), for side-by-side comparison only. Not used by the fixed
# gate - this function exists solely so the self-test can demonstrate the
# defect it closes.
pre_fix_expected_files() {
  local root="$1"
  find "$root/server/test" -name "*.test.ts" -not -path "*/node_modules/*" | wc -l | tr -d '[:space:]'
}

pre_fix_check_passes() {
  local root="$1" actual_total="$2"
  local expected
  expected="$(pre_fix_expected_files "$root")"
  # Mirrors: if (( actual_total < expected_files )); then <fail>; fi
  if (( actual_total < expected )); then
    return 1
  fi
  return 0
}

# Reproduces round 2's fix (server/scripts/count-vitest-test-files.mjs
# before the vitest-list-based rewrite this self-test also proves): glob
# BOTH test.include roots by hand, but with no idea that test.exclude
# exists. Not used by the fixed gate - exists only so Case 4 can show that
# round 2, while it fixed round 1's missing-root bug, could still
# false-fail a perfectly healthy run the moment vitest.config.ts grows a
# config surface it didn't model.
round2_expected_files() {
  local root="$1"
  {
    find "$root/server/test" -name "*.test.ts" -not -path "*/node_modules/*"
    find "$root/scripts/synthetic-coverage/test" -name "*.test.ts" -not -path "*/node_modules/*" 2>/dev/null
  } | wc -l | tr -d '[:space:]'
}

make_vitest_log() {
  local path="$1" total="$2"
  printf ' Test Files  %s passed (%s)\n Tests  10 passed (10)\n' "$total" "$total" > "$path"
}

# Builds a fixture with REAL, runnable test files (vitest's own `it`/`expect`
# globals, no imports needed) and a REAL test.exclude entry, so Case 4 can
# drive gate2b-check.sh from an ACTUAL `vitest run` + `vitest list
# --filesOnly` invocation rather than a fabricated summary line. This is the
# fixture shape that answers the "exclude/dot/project divergence is outside
# this self-test's proof" gap: fixtures 1-3 test the COMPARISON logic against
# a controlled, fabricated actual_total; this one tests that the DISCOVERY
# side (count-vitest-test-files.mjs) agrees with vitest's real behavior when
# a config surface round 2's hand-rolled glob never modeled is in play.
build_real_vitest_fixture() {
  local root="$1"
  local server_test_count="$2"   # files under server/test
  local synthetic_count="$3"     # files under scripts/synthetic-coverage/test
  local excluded_rel="$4"        # e.g. "test/fixture-5.test.ts" - real to disk, real to test.include, excluded from test.exclude

  mkdir -p "$root/server/scripts" "$root/scripts/synthetic-coverage/test" "$root/server/test"

  cp "$SCRIPT_DIR/gate2b-check.sh" "$root/scripts/gate2b-check.sh"
  chmod +x "$root/scripts/gate2b-check.sh"
  cp "$REPO_ROOT/server/scripts/count-vitest-test-files.mjs" "$root/server/scripts/count-vitest-test-files.mjs"
  ln -s "$REPO_ROOT/server/node_modules" "$root/server/node_modules"

  write_file "$root" "server/package.json" '{"type": "module"}
'
  write_file "$root" "server/vitest.config.ts" "import { defineConfig } from \"vitest/config\";

export default defineConfig({
  test: {
    globals: true,
    environment: \"node\",
    include: [\"test/**/*.test.ts\", \"../scripts/synthetic-coverage/test/**/*.test.ts\"],
    exclude: [\"$excluded_rel\"],
  },
});
"

  for i in $(seq 1 "$server_test_count"); do
    write_file "$root" "server/test/fixture-$i.test.ts" "it('real fixture $i', () => { expect(1 + 1).toBe(2); });
"
  done
  for i in $(seq 1 "$synthetic_count"); do
    write_file "$root" "scripts/synthetic-coverage/test/fixture-$i.test.ts" "it('real synthetic fixture $i', () => { expect(1 + 1).toBe(2); });
"
  done
}

run_case() {
  local name="$1"
  echo "── $name"
}

# ── Case 1: no drop - fixed check passes ────────────────────────────
run_case "no drop: fixed check passes"
FIXTURE_1="$(mktemp -d)"
CLEANUP_DIRS+=("$FIXTURE_1")
build_fixture "$FIXTURE_1" 5 2
make_vitest_log "$FIXTURE_1/vitest-output.log" 7
set +e
bash "$FIXTURE_1/scripts/gate2b-check.sh" "$FIXTURE_1/vitest-output.log" > "$FIXTURE_1/stdout.log" 2>&1
status1=$?
set -e
[[ "$status1" == "0" ]] || fail "expected exit 0 with no drop, got $status1:
$(cat "$FIXTURE_1/stdout.log")"
grep -q '^7$' <(node "$FIXTURE_1/server/scripts/count-vitest-test-files.mjs") \
  || fail "expected count script to report 7 (5 + 2) for the no-drop fixture"
echo "  ok: fixed check exits 0 when nothing dropped (expected=7, actual=7)"

# ── Case 2: planted drop - fixed check FAILS, pre-fix formula PASSES ─
# One server/test file "silently fails to load": it stays ON DISK (the
# defect this proves is about vitest skipping a file during collection, not
# about a file being deleted - deletion alone is already caught by the
# pre-fix formula since expected_files would also drop). What changes is
# vitest's own reported total, which is what a real transform/collection
# failure would produce: the file is present but never counted.
run_case "planted drop (1 of 5 server/test files silently fails to load): fixed check fails, pre-fix formula passes"
FIXTURE_2="$(mktemp -d)"
CLEANUP_DIRS+=("$FIXTURE_2")
build_fixture "$FIXTURE_2" 5 2
# actual_total = (5 - 1) + 2 = 6, simulating vitest silently dropping one
# server/test file while both synthetic-coverage files still load.
make_vitest_log "$FIXTURE_2/vitest-output.log" 6

set +e
bash "$FIXTURE_2/scripts/gate2b-check.sh" "$FIXTURE_2/vitest-output.log" > "$FIXTURE_2/stdout.log" 2>&1
status2=$?
set -e
[[ "$status2" == "1" ]] || fail "expected the FIXED check to fail (exit 1) on a planted drop, got $status2:
$(cat "$FIXTURE_2/stdout.log")"
grep -q 'Silent test file drop detected' "$FIXTURE_2/stdout.log" \
  || fail "expected drop message in output:
$(cat "$FIXTURE_2/stdout.log")"
grep -q 'Missing 1 file(s)' "$FIXTURE_2/stdout.log" \
  || fail "expected 'Missing 1 file(s)' in output:
$(cat "$FIXTURE_2/stdout.log")"
echo "  ok: fixed check reports the drop (expected=7, actual=6, missing=1)"

# Now prove the DEFECT this replaces: same fixture, same planted actual_total
# (6), but the PRE-FIX expected_files formula (find server/test only, ignoring
# the synthetic-coverage root) computes 5, not 7 - and 6 is NOT less than 5,
# so the old gate would have reported success on the exact same silent drop.
if pre_fix_check_passes "$FIXTURE_2" 6; then
  old_expected="$(pre_fix_expected_files "$FIXTURE_2")"
  echo "  ok: reproduced the pre-fix defect - old formula computed expected_files=$old_expected (server/test only), actual_total=6 was NOT < $old_expected, so the OLD gate would have PASSED on this same dropped file"
else
  fail "expected the pre-fix formula to (incorrectly) pass on this planted drop - if it now fails, the reproduction of the historical defect is wrong and this self-test needs to be revisited"
fi

# ── Case 3: surplus is now a HARD FAILURE, not tolerated informational ──
# An earlier version of this gate tolerated actual_total > expected_files
# (expected_files was a static glob model that could plausibly undercount a
# runtime edge case). That is no longer true: both sides now come from
# vitest's own discovery/run against the same checkout, so a surplus means
# the two vitest invocations disagreed with each other, which is exactly as
# untrustworthy as a shortfall - this case proves the gate no longer lets it
# through as a "not a drop, don't worry about it" note.
run_case "surplus: actual_total > expected_files is now a hard failure (equality required)"
FIXTURE_3="$(mktemp -d)"
CLEANUP_DIRS+=("$FIXTURE_3")
build_fixture "$FIXTURE_3" 5 2
make_vitest_log "$FIXTURE_3/vitest-output.log" 8
set +e
bash "$FIXTURE_3/scripts/gate2b-check.sh" "$FIXTURE_3/vitest-output.log" > "$FIXTURE_3/stdout.log" 2>&1
status3=$?
set -e
[[ "$status3" == "1" ]] || fail "expected exit 1 on surplus (equality required), got $status3:
$(cat "$FIXTURE_3/stdout.log")"
grep -q 'Unexpected surplus' "$FIXTURE_3/stdout.log" \
  || fail "expected the surplus error message in output:
$(cat "$FIXTURE_3/stdout.log")"
echo "  ok: surplus fails (equality enforced), not silently tolerated"

# ── Case 4: REAL vitest run + a REAL test.exclude entry ──────────────
#
# Cases 1-3 fabricate the "actual_total" side to test the COMPARISON logic
# deterministically. This case drives BOTH sides for real: an actual `vitest
# run` produces the vitest-output log gate2b-check.sh parses, and an actual
# `vitest list --filesOnly` (inside count-vitest-test-files.mjs) produces
# expected_files - against a fixture whose vitest.config.ts carries a REAL
# test.exclude entry, the exact config surface round 2's hand-rolled
# tinyglobby-over-test.include glob had no idea existed.
#
#   - On disk: 5 files under server/test + 2 under synthetic-coverage = 7
#     files match test.include.
#   - test.exclude drops 1 of the server/test files, so vitest's REAL
#     discovery and REAL run both land on 6.
#   - The FIXED counter (vitest list --filesOnly) reports 6 - it respects
#     exclude because it asks vitest, not because this script re-implements
#     the rule - so gate2b-check.sh sees expected=6, actual=6 and PASSES on
#     a perfectly healthy run.
#   - The ROUND-2 counter (glob test.include by hand, no exclude support)
#     would have reported 7. Fed the SAME real actual_total=6, round 2's
#     `actual_total < expected_files` (6 < 7) would have FALSE-FAILED this
#     healthy run - the "false failure" direction of the finding this fixes,
#     demonstrated against vitest's real behavior rather than asserted.
run_case "real vitest run + real test.exclude: fixed check passes, round-2 formula would have false-failed a healthy run"
FIXTURE_4="$(mktemp -d)"
CLEANUP_DIRS+=("$FIXTURE_4")
build_real_vitest_fixture "$FIXTURE_4" 5 2 "test/fixture-5.test.ts"

VITEST_BIN="$FIXTURE_4/server/node_modules/.bin/vitest"
[[ -x "$VITEST_BIN" ]] || fail "vitest binary not found at $VITEST_BIN - is server/node_modules present in this worktree?"

set +e
(
  cd "$FIXTURE_4/server"
  NO_COLOR=1 FORCE_COLOR=0 "$VITEST_BIN" run > "$FIXTURE_4/vitest-real-output.log" 2>&1
)
real_run_status=$?
set -e
[[ "$real_run_status" == "0" ]] || fail "expected the real vitest run to pass (nothing is actually broken in this fixture), got exit $real_run_status:
$(cat "$FIXTURE_4/vitest-real-output.log")"
grep -q 'Test Files  6 passed (6)' "$FIXTURE_4/vitest-real-output.log" \
  || fail "expected the real vitest run to report 'Test Files  6 passed (6)' (7 on disk minus 1 excluded), got:
$(cat "$FIXTURE_4/vitest-real-output.log")"

new_expected="$(node "$FIXTURE_4/server/scripts/count-vitest-test-files.mjs")"
[[ "$new_expected" == "6" ]] || fail "expected the fixed counter to report 6 (respecting test.exclude), got $new_expected"

set +e
bash "$FIXTURE_4/scripts/gate2b-check.sh" "$FIXTURE_4/vitest-real-output.log" > "$FIXTURE_4/gate2b-stdout.log" 2>&1
status4=$?
set -e
[[ "$status4" == "0" ]] || fail "expected the fixed check to pass against a real vitest run with a real exclude, got $status4:
$(cat "$FIXTURE_4/gate2b-stdout.log")"
echo "  ok: fixed check passes against a real vitest run (expected=6, actual=6, exclude respected)"

round2_expected="$(round2_expected_files "$FIXTURE_4")"
[[ "$round2_expected" == "7" ]] || fail "expected the round-2 reproduction to compute 7 (test.exclude ignored), got $round2_expected"
if (( 6 < round2_expected )); then
  echo "  ok: reproduced round 2's blind spot - its formula would have computed expected_files=$round2_expected (test.exclude ignored) against this SAME real run's actual_total=6, so round 2 would have FALSE-FAILED a healthy run"
else
  fail "expected round 2's reproduction (7) to exceed the real actual_total (6) - if it doesn't, this case no longer demonstrates the false-failure direction and needs to be revisited"
fi

echo ""
echo "PASS: gate2b-check.sh self-test"
