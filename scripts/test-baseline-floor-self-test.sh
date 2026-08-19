#!/usr/bin/env bash
#
# Self-tests for scripts/test-baseline-floor.sh
# Copyright 2026 Erik Newton
# SPDX-License-Identifier: Apache-2.0
#
# Runs in a few seconds against disposable fixtures. It needs neither Node nor
# an installed suite, so the workflow runs it before `npm ci`: a broken floor
# guard should red in seconds, not after a two-minute install.
#
# Every case below is a decision the floor mechanism makes in CI. The point of
# the file is that those decisions are exercisable without merging a branch and
# watching main, which is how the previous attempt at this mechanism had to be
# tested.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLOOR_SCRIPT="$SCRIPT_DIR/test-baseline-floor.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUARD_WORKFLOW="$REPO_ROOT/.github/workflows/test-baseline-guard.yml"

# Real vitest summary output, ANSI-free, captured from a run of this repo's
# suite with NO_COLOR=1 (the same environment the workflow sets). The parser is
# tested against vitest's actual formatting rather than a hand-written
# approximation of it, because a summary-format change is exactly the drift that
# would make the parser silently stop matching.
VITEST_LOG_BODY=' Test Files  1 passed (1)
      Tests  2 passed (2)
   Start at  14:55:25
   Duration  2.14s (transform 968ms, setup 12ms, import 1.26s, tests 802ms, environment 0ms)
'
VITEST_LOG_COUNT=2

PASSED=0

fail() {
  echo "SELF-TEST FAIL: $*" >&2
  exit 1
}

# Runs the floor script, capturing status, stdout and stderr into the fixture
# root so a failing assertion can print everything the run produced.
run_floor() {
  local root="$1"
  shift
  set +e
  ( cd "$root" && bash "$FLOOR_SCRIPT" "$@" ) > "$root/stdout.log" 2> "$root/stderr.log"
  local status=$?
  set -e
  printf '%s\n' "$status" > "$root/status"
}

assert_status() {
  local root="$1"
  local expected="$2"
  local actual
  actual="$(cat "$root/status")"
  [[ "$actual" == "$expected" ]] || fail "expected exit $expected, got $actual
stdout:
$(cat "$root/stdout.log")
stderr:
$(cat "$root/stderr.log")"
}

assert_stdout_contains() {
  local root="$1"
  local needle="$2"
  grep -Fq "$needle" "$root/stdout.log" || fail "stdout did not contain: $needle
stdout:
$(cat "$root/stdout.log")"
}

assert_stderr_contains() {
  local root="$1"
  local needle="$2"
  grep -Fq "$needle" "$root/stderr.log" || fail "stderr did not contain: $needle
stderr:
$(cat "$root/stderr.log")"
}

assert_file_equals() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(tr -d '[:space:]' < "$path")"
  [[ "$actual" == "$expected" ]] || fail "$path holds '$actual', expected '$expected'"
}

write_vitest_log() {
  local root="$1"
  printf '%s' "$VITEST_LOG_BODY" > "$root/vitest.log"
}

# ── The pull-request gate ───────────────────────────────────────────────────

# The planted divergence. A floor one above what the suite actually counted is
# the regression this gate exists to catch, and the case is built from a REAL
# vitest log rather than a bare integer so the parse and the comparison are
# proven together. An unproven guard is not evidence that anything is guarded.
case_below_floor_fails() {
  local root="$1"
  write_vitest_log "$root"
  printf '%s\n' "$((VITEST_LOG_COUNT + 1))" > "$root/.test-baseline"

  run_floor "$root" read-floor .test-baseline
  assert_status "$root" 0
  local floor
  floor="$(cat "$root/stdout.log")"

  run_floor "$root" parse-count vitest.log
  assert_status "$root" 0
  local observed
  observed="$(cat "$root/stdout.log")"
  [[ "$observed" == "$VITEST_LOG_COUNT" ]] || fail "parse-count read '$observed' from a real vitest log, expected $VITEST_LOG_COUNT"

  run_floor "$root" assert-not-below "$floor" "$observed"
  assert_status "$root" 1
  assert_stderr_contains "$root" "test baseline regression"
  assert_stderr_contains "$root" "Missing 1 tests"
  # The gate must not repair what it caught.
  assert_file_equals "$root/.test-baseline" "$((VITEST_LOG_COUNT + 1))"
}

case_equal_to_floor_passes() {
  local root="$1"
  write_vitest_log "$root"
  printf '%s\n' "$VITEST_LOG_COUNT" > "$root/.test-baseline"
  run_floor "$root" assert-not-below "$VITEST_LOG_COUNT" "$VITEST_LOG_COUNT"
  assert_status "$root" 0
  assert_stdout_contains "$root" "exactly at the recorded floor"
  assert_file_equals "$root/.test-baseline" "$VITEST_LOG_COUNT"
}

# Above the floor is the ordinary resting state under this design: a pull
# request that adds tests counts higher than the floor main recorded, and it
# passes without anyone typing the new number. Under the previous rule this same
# state was a hard failure demanding an integer computed on a platform the
# author cannot run, which is what made three of three pull requests on
# 2026-08-19 guess it wrong.
case_above_floor_passes_and_writes_nothing() {
  local root="$1"
  write_vitest_log "$root"
  printf '%s\n' "$((VITEST_LOG_COUNT - 1))" > "$root/.test-baseline"
  local before
  before="$(cat "$root/.test-baseline")"

  run_floor "$root" assert-not-below "$((VITEST_LOG_COUNT - 1))" "$VITEST_LOG_COUNT"
  assert_status "$root" 0
  assert_stdout_contains "$root" "above the recorded floor"
  # The whole point of the redesign: no write is attempted on the pull-request
  # side, so the file is byte-identical after the gate ran.
  [[ "$(cat "$root/.test-baseline")" == "$before" ]] \
    || fail "the pull-request gate modified .test-baseline"
}

# ── Fail-closed parsing ─────────────────────────────────────────────────────

case_malformed_floor_refuses() {
  local root="$1"
  printf 'fourteen thousand\n' > "$root/.test-baseline"
  run_floor "$root" read-floor .test-baseline
  assert_status "$root" 2
  assert_stderr_contains "$root" "must be a plain non-negative integer"
}

# A leading-zero floor would be read as octal by the arithmetic comparisons and
# would silently understate itself, so it is refused rather than normalized.
case_leading_zero_floor_refuses() {
  local root="$1"
  printf '007\n' > "$root/.test-baseline"
  run_floor "$root" read-floor .test-baseline
  assert_status "$root" 2
}

case_missing_floor_refuses() {
  local root="$1"
  run_floor "$root" read-floor .test-baseline
  assert_status "$root" 2
  assert_stderr_contains "$root" "is missing"
}

# An unparseable suite summary must never read as "no regression". This is the
# absent-versus-failed conflation the whole guard exists to prevent.
case_unparseable_suite_output_refuses() {
  local root="$1"
  printf 'the runner died before it printed a summary\n' > "$root/vitest.log"
  run_floor "$root" parse-count vitest.log
  assert_status "$root" 2
  assert_stderr_contains "$root" "Refusing rather than assuming zero regression"
}

# ── The recording decision on main ──────────────────────────────────────────

case_record_decision_records_when_different() {
  local root="$1"
  run_floor "$root" record-decision 100 137
  assert_status "$root" 0
  assert_stdout_contains "$root" "record: 100 -> 137"
}

case_record_decision_no_action_when_correct() {
  local root="$1"
  run_floor "$root" record-decision 137 137
  assert_status "$root" 10
  assert_stdout_contains "$root" "already 137"
}

# The floor already being correct must produce no commit at all. Writing the
# same bytes back would produce an empty commit or a no-op push on every merge,
# which is noise that trains a reader to ignore the one commit that matters.
case_record_already_correct_leaves_file_untouched() {
  local root="$1"
  printf '137\n' > "$root/.test-baseline"
  local before_hash
  before_hash="$(cksum < "$root/.test-baseline")"
  run_floor "$root" record .test-baseline 137
  assert_status "$root" 10
  assert_stdout_contains "$root" "not writing"
  [[ "$(cksum < "$root/.test-baseline")" == "$before_hash" ]] \
    || fail "record rewrote a floor that was already correct"
}

case_record_writes_when_different() {
  local root="$1"
  printf '100\n' > "$root/.test-baseline"
  run_floor "$root" record .test-baseline 137
  assert_status "$root" 0
  assert_file_equals "$root/.test-baseline" 137
}

# A deliberate, reviewed test removal lands as a LOWER recorded floor. The
# recorder describes main rather than arguing with it; the argument happened in
# the pull request that removed the tests.
case_record_accepts_a_deliberate_lowering() {
  local root="$1"
  printf '137\n' > "$root/.test-baseline"
  run_floor "$root" record .test-baseline 120
  assert_status "$root" 0
  assert_file_equals "$root/.test-baseline" 120
}

# ── Context guards on the recorder ──────────────────────────────────────────

case_record_refuses_off_main() {
  local root="$1"
  run_floor "$root" guard-record-context refs/heads/feature/some-branch "feat: something"
  assert_status "$root" 1
  assert_stderr_contains "$root" "recorded on refs/heads/main only"
}

# The loop bound. The subject the recorder REFUSES is generated by the same
# subcommand that produces the subject it WRITES, so the two cannot drift into a
# recorder that does not recognize its own commits and pushes forever.
case_record_refuses_its_own_commit() {
  local root="$1"
  run_floor "$root" commit-subject 14338
  assert_status "$root" 0
  local subject
  subject="$(cat "$root/stdout.log")"
  [[ "$subject" == "chore(ci): record .test-baseline 14338 after merge" ]] \
    || fail "commit-subject produced an unexpected subject: '$subject'"

  run_floor "$root" guard-record-context refs/heads/main "$subject"
  assert_status "$root" 1
  assert_stderr_contains "$root" "recording again would loop"
}

case_record_permitted_on_main_after_an_ordinary_merge() {
  local root="$1"
  run_floor "$root" guard-record-context refs/heads/main "feat(state): something real (#1234)"
  assert_status "$root" 0
  assert_stdout_contains "$root" "recording is permitted"
}

# ── The scheduled drift backstop ────────────────────────────────────────────

case_drift_in_sync() {
  local root="$1"
  run_floor "$root" drift-verdict 137 137 999999 3600
  assert_status "$root" 0
  assert_stdout_contains "$root" "IN-SYNC"
}

case_drift_within_window_is_not_reported() {
  local root="$1"
  run_floor "$root" drift-verdict 137 140 60 3600
  assert_status "$root" 0
  assert_stdout_contains "$root" "DRIFT-WITHIN-WINDOW"
}

case_drift_past_window_reports() {
  local root="$1"
  run_floor "$root" drift-verdict 137 140 7200 3600
  assert_status "$root" 1
  assert_stderr_contains "$root" "has been stale"
  assert_stderr_contains "$root" "indistinguishable from a healthy one"
}

# Drift age is measured from the first commit AFTER the floor's last change, so
# a busy branch cannot keep persistent drift permanently inside the grace
# window by continuously producing young commits.
case_drift_age_measures_from_the_first_unrecorded_commit() {
  local root="$1"
  git -C "$root" init --quiet
  git -C "$root" config --local user.email test@example.com
  git -C "$root" config --local user.name "Floor Self Test"

  printf '100\n' > "$root/.test-baseline"
  git -C "$root" add .test-baseline
  git -C "$root" commit --quiet --no-verify -m "record the floor"

  run_floor "$root" drift-age-seconds .test-baseline
  assert_status "$root" 0
  [[ "$(cat "$root/stdout.log")" == "0" ]] \
    || fail "a floor that is the newest change should report zero drift age, got $(cat "$root/stdout.log")"

  # Two commits land after the floor. The FIRST of them dates the drift; the
  # second is newer and must not reset the clock.
  printf 'one\n' > "$root/other.txt"
  git -C "$root" add other.txt
  GIT_COMMITTER_DATE="@$(( $(date -u +%s) - 7200 )) +0000" \
    git -C "$root" commit --quiet --no-verify --date "@$(( $(date -u +%s) - 7200 )) +0000" -m "first commit after the floor"
  printf 'two\n' > "$root/other.txt"
  git -C "$root" add other.txt
  git -C "$root" commit --quiet --no-verify -m "a much newer commit"

  run_floor "$root" drift-age-seconds .test-baseline
  assert_status "$root" 0
  local age
  age="$(cat "$root/stdout.log")"
  (( age >= 7000 )) || fail "drift age reset to the newest commit: got ${age}s, expected roughly 7200s"
}

# ── Cross-file pins: the workflow must keep the write where it belongs ──────

workflow_line_of() {
  grep -nE "$1" "$GUARD_WORKFLOW" | head -1 | cut -d: -f1
}

# INVARIANT this case pins: exactly one job in the guard workflow holds a write
# token, and it is the record-floor job. If a future edit moves `contents: write`
# up to the workflow level or onto the pull-request job, the pull request's own
# test code executes with push authority, which is precisely the finding that
# killed the previous design.
case_only_the_record_job_can_write() {
  local root="$1"
  local write_lines
  write_lines="$(grep -cE '^[[:space:]]+contents:[[:space:]]*write[[:space:]]*$' "$GUARD_WORKFLOW" || true)"
  [[ "$write_lines" == "1" ]] \
    || fail "$GUARD_WORKFLOW declares 'contents: write' $write_lines times; exactly one, inside record-floor, is allowed"

  local record_job_line write_line
  record_job_line="$(workflow_line_of '^  record-floor:')"
  write_line="$(workflow_line_of '^[[:space:]]+contents:[[:space:]]*write[[:space:]]*$')"
  [[ -n "$record_job_line" ]] || fail "$GUARD_WORKFLOW has no record-floor job"
  (( write_line > record_job_line )) \
    || fail "'contents: write' at line $write_line sits outside the record-floor job (line $record_job_line)"

  # And every mutating invocation of the floor script sits inside that job too.
  local mutating_line
  while IFS=: read -r mutating_line _; do
    [[ -z "$mutating_line" ]] && continue
    (( mutating_line > record_job_line )) \
      || fail "a mutating floor-script call at line $mutating_line sits outside the record-floor job"
  done < <(grep -nE 'test-baseline-floor\.sh (record|commit-subject)' "$GUARD_WORKFLOW" || true)

  # A no-op read so the fixture root is used and the case shape matches the rest.
  [[ -d "$root" ]] || fail "fixture root vanished"
}

# The guard workflow and this script must agree on the recorded-floor commit
# subject. The workflow gets it by calling `commit-subject`; this case pins that
# it does not spell the subject out a second time, which is how the recognizer
# and the writer would drift apart.
case_workflow_does_not_hardcode_the_commit_subject() {
  local root="$1"
  local hardcoded
  hardcoded="$(grep -E "chore\(ci\): record" "$GUARD_WORKFLOW" | grep -vc 'commit-subject' || true)"
  [[ "$hardcoded" == "0" ]] \
    || fail "the guard workflow hardcodes the recorded-floor commit subject on $hardcoded line(s); call commit-subject instead"
  [[ -d "$root" ]] || fail "fixture root vanished"
}

run_case() {
  local name="$1"
  local fn="$2"
  local root
  root="$(mktemp -d "${TMPDIR:-/tmp}/sanctuary-baseline-floor.XXXXXX")"
  "$fn" "$root"
  rm -rf "$root"
  PASSED=$((PASSED + 1))
  echo "PASS: $name"
}

run_case "a count below the recorded floor reds the pull-request gate" case_below_floor_fails
run_case "a count equal to the floor passes" case_equal_to_floor_passes
run_case "a count above the floor passes and writes nothing" case_above_floor_passes_and_writes_nothing
run_case "a malformed floor is refused, not guessed" case_malformed_floor_refuses
run_case "a leading-zero floor is refused rather than read as octal" case_leading_zero_floor_refuses
run_case "a missing floor is refused" case_missing_floor_refuses
run_case "an unparseable suite summary is refused, never read as passing" case_unparseable_suite_output_refuses
run_case "the recorder records when the count differs" case_record_decision_records_when_different
run_case "the recorder takes no action when the floor is already correct" case_record_decision_no_action_when_correct
run_case "an already-correct floor is not rewritten" case_record_already_correct_leaves_file_untouched
run_case "a differing count is written to the floor" case_record_writes_when_different
run_case "a deliberate lowering is recorded, not clamped" case_record_accepts_a_deliberate_lowering
run_case "the recorder refuses to run off main" case_record_refuses_off_main
run_case "the recorder refuses its own commit, bounding the loop" case_record_refuses_its_own_commit
run_case "the recorder proceeds on main after an ordinary merge" case_record_permitted_on_main_after_an_ordinary_merge
run_case "drift reports in sync when the floor matches a fresh count" case_drift_in_sync
run_case "drift younger than the window is not reported" case_drift_within_window_is_not_reported
run_case "drift older than the window is reported loudly" case_drift_past_window_reports
run_case "drift age is measured from the first unrecorded commit" case_drift_age_measures_from_the_first_unrecorded_commit
run_case "only the record-floor job holds a write token" case_only_the_record_job_can_write
run_case "the workflow does not hardcode the recorded-floor commit subject" case_workflow_does_not_hardcode_the_commit_subject

echo "PASS: test-baseline-floor self-tests ($PASSED cases)"
