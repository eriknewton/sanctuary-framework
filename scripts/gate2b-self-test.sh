#!/usr/bin/env bash
set -euo pipefail

# Self-test for scripts/gate2b-check.sh (and, by extension, the identical
# logic inlined at .githooks/pre-commit's `expected_files=$(node
# server/scripts/count-vitest-test-files.mjs ...)` line).
#
# Proves two things against a throwaway fixture whose vitest.config.ts has
# the same shape as server/vitest.config.ts (two test.include roots):
#
#   1. The FIXED check (gate2b-check.sh, deriving expected_files from the
#      include globs across BOTH roots) correctly FAILS when a server/test
#      file silently stops loading, even though the file is still present on
#      disk (the exact commit-4ac95830 shape: a transform/collection error
#      drops a file from the run without vitest exiting non-zero on its own).
#   2. The PRE-FIX check (a `find server/test` restated inline below, the
#      literal formula this fix replaced) PASSES on the exact same planted
#      drop, because the untracked second include root's file count was
#      masking it. This is the 992-vs-1006 / 14-file-cushion defect,
#      reproduced at a small scale (5 + 2 files) so it runs in milliseconds.
#
# Mirrors the fixture-and-assert shape of scripts/verify-fail-before-self-test.sh.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# All fixture dirs get cleaned up on ANY exit path (success, `fail`, or an
# unexpected error under `set -e`), not just the happy path — a case that
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
# a second copy for a throwaway fixture would be slow and pointless — the
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

  # "type": "module" mirrors server/package.json — without it, Vite's config
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
# gate — this function exists solely so the self-test can demonstrate the
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

make_vitest_log() {
  local path="$1" total="$2"
  printf ' Test Files  %s passed (%s)\n Tests  10 passed (10)\n' "$total" "$total" > "$path"
}

run_case() {
  local name="$1"
  echo "── $name"
}

# ── Case 1: no drop — fixed check passes ────────────────────────────
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

# ── Case 2: planted drop — fixed check FAILS, pre-fix formula PASSES ─
# One server/test file "silently fails to load": it stays ON DISK (the
# defect this proves is about vitest skipping a file during collection, not
# about a file being deleted — deletion alone is already caught by the
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
# the synthetic-coverage root) computes 5, not 7 — and 6 is NOT less than 5,
# so the old gate would have reported success on the exact same silent drop.
if pre_fix_check_passes "$FIXTURE_2" 6; then
  old_expected="$(pre_fix_expected_files "$FIXTURE_2")"
  echo "  ok: reproduced the pre-fix defect — old formula computed expected_files=$old_expected (server/test only), actual_total=6 was NOT < $old_expected, so the OLD gate would have PASSED on this same dropped file"
else
  fail "expected the pre-fix formula to (incorrectly) pass on this planted drop — if it now fails, the reproduction of the historical defect is wrong and this self-test needs to be revisited"
fi

# ── Case 3: surplus (informational only, not a failure) ─────────────
run_case "surplus: actual_total > expected_files logs a note but still exits 0"
FIXTURE_3="$(mktemp -d)"
CLEANUP_DIRS+=("$FIXTURE_3")
build_fixture "$FIXTURE_3" 5 2
make_vitest_log "$FIXTURE_3/vitest-output.log" 8
set +e
bash "$FIXTURE_3/scripts/gate2b-check.sh" "$FIXTURE_3/vitest-output.log" > "$FIXTURE_3/stdout.log" 2>&1
status3=$?
set -e
[[ "$status3" == "0" ]] || fail "expected exit 0 on surplus (not a drop), got $status3:
$(cat "$FIXTURE_3/stdout.log")"
grep -q 'Note: vitest loaded more files' "$FIXTURE_3/stdout.log" \
  || fail "expected an informational surplus note in output:
$(cat "$FIXTURE_3/stdout.log")"
echo "  ok: surplus is logged, not failed"

echo ""
echo "PASS: gate2b-check.sh self-test (3/3 cases)"
