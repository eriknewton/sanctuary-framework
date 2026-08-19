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
# watching main, which is how earlier versions of this mechanism had to be
# tested.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLOOR_SCRIPT="$SCRIPT_DIR/test-baseline-floor.sh"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GUARD_WORKFLOW="$REPO_ROOT/.github/workflows/test-baseline-guard.yml"
DRIFT_WORKFLOW="$REPO_ROOT/.github/workflows/test-baseline-floor-drift.yml"

# Real vitest summary output, ANSI-free, captured from a run of this repo's
# suite with NO_COLOR=1 (the same environment the workflows set). The parser is
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

assert_stdout_is() {
  local root="$1"
  local expected="$2"
  local actual
  actual="$(cat "$root/stdout.log")"
  [[ "$actual" == "$expected" ]] || fail "stdout was '$actual', expected exactly '$expected'
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
  run_floor "$root" assert-not-below "$VITEST_LOG_COUNT" "$VITEST_LOG_COUNT"
  assert_status "$root" 0
  assert_stdout_contains "$root" "exactly at the floor in force"
}

# Above the floor is the ordinary resting state under this design: a change that
# adds tests counts higher than the floor the default branch published, and it
# passes without anyone typing the new number. Under the previous rule this same
# state was a hard failure demanding an integer computed on a platform the author
# cannot run, which is what made three of three pull requests on 2026-08-19 guess
# it wrong.
case_above_floor_passes_and_writes_nothing() {
  local root="$1"
  printf '%s\n' "$((VITEST_LOG_COUNT - 1))" > "$root/.test-baseline"
  local before
  before="$(cat "$root/.test-baseline")"

  run_floor "$root" assert-not-below "$((VITEST_LOG_COUNT - 1))" "$VITEST_LOG_COUNT"
  assert_status "$root" 0
  assert_stdout_contains "$root" "above the floor in force"
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

# ── Choosing the floor in force ─────────────────────────────────────────────

# The ordinary path: the default branch published a count above the slow-moving
# committed fallback, so that count is the floor.
case_cache_hit_above_fallback_wins() {
  local root="$1"
  run_floor "$root" effective-floor 14000 14338
  assert_status "$root" 0
  assert_stdout_is "$root" 14338
  assert_stderr_contains "$root" "CACHED-FLOOR-IN-FORCE"
}

case_cache_hit_equal_to_fallback() {
  local root="$1"
  run_floor "$root" effective-floor 14338 14338
  assert_status "$root" 0
  assert_stdout_is "$root" 14338
  assert_stderr_contains "$root" "CACHED-FLOOR-IN-FORCE"
}

# A missing cache entry is expected, not exceptional: a first run, an evicted
# entry, a restricted fork pull request. It must route to the committed fallback
# AND say so. A fallback preferred quietly is indistinguishable from a healthy
# cached floor and asserts less, which is the exact failure this design is trying
# not to reintroduce.
case_cache_miss_falls_back_and_says_so() {
  local root="$1"
  run_floor "$root" effective-floor 14338 ""
  assert_status "$root" 0
  assert_stdout_is "$root" 14338
  assert_stderr_contains "$root" "FALLBACK-IN-FORCE"
  assert_stderr_contains "$root" "no cached count from the default branch was available"
}

# An unreadable entry is more alarming than a missing one, and the message says
# which it was. Both are safe; only one means something wrote a cache this gate
# cannot parse.
case_cache_unreadable_falls_back_and_says_which() {
  local root="$1"
  run_floor "$root" effective-floor 14338 "not-a-number"
  assert_status "$root" 0
  assert_stdout_is "$root" 14338
  assert_stderr_contains "$root" "present but unreadable"
}

# THE PROOF THAT A LOW CACHE CANNOT WEAKEN THE COMMITTED FLOOR. The cache is
# written by CI and reviewed by nobody, so an evicted, truncated, stale, or
# out-of-order entry must never lower a number a human committed on purpose.
case_cache_below_fallback_does_not_weaken_it() {
  local root="$1"
  run_floor "$root" effective-floor 14338 9000
  assert_status "$root" 0
  assert_stdout_is "$root" 14338
  assert_stderr_contains "$root" "COMMITTED-FLOOR-IN-FORCE"
  assert_stderr_contains "$root" "never lowers the floor"
}

# The same fact, carried all the way to a verdict, because "the higher number is
# printed" is not the same claim as "the gate actually reds". A change counting
# between the low cached value and the committed fallback would pass if the
# cached value won, and must fail because it does not.
case_cache_below_fallback_still_reds_the_gate() {
  local root="$1"
  run_floor "$root" effective-floor 14338 9000
  assert_status "$root" 0
  local floor
  floor="$(cat "$root/stdout.log")"
  run_floor "$root" assert-not-below "$floor" 10000
  assert_status "$root" 1
  assert_stderr_contains "$root" "Missing 4338 tests"
}

# ── Deciding whether to publish ─────────────────────────────────────────────

case_publish_on_main_at_the_tip() {
  local root="$1"
  run_floor "$root" publish-decision refs/heads/main aaaa1111 aaaa1111
  assert_status "$root" 0
  assert_stdout_contains "$root" "publishing the observed count"
}

case_publish_declines_off_the_default_branch() {
  local root="$1"
  run_floor "$root" publish-decision refs/heads/feature/x aaaa1111 aaaa1111
  assert_status "$root" 1
  assert_stderr_contains "$root" "published from refs/heads/main only"
}

# Two pushes can finish out of order, and the restore side takes the most
# recently CREATED entry, so an older run finishing late would otherwise
# overwrite a newer count with an older one. It declines instead.
case_publish_declines_when_the_branch_moved() {
  local root="$1"
  run_floor "$root" publish-decision refs/heads/main aaaa1111 bbbb2222
  assert_status "$root" 1
  assert_stderr_contains "$root" "the newer push publishes its own count"
}

# ── The scheduled fallback-decay backstop ───────────────────────────────────

case_fallback_in_sync() {
  local root="$1"
  run_floor "$root" fallback-drift-verdict 14338 14338 999999 604800 250
  assert_status "$root" 0
  assert_stdout_contains "$root" "IN-SYNC"
}

# The fallback sitting ABOVE a fresh count is unconditionally news: every pull
# request that falls back to it reds with a regression that is not one.
case_fallback_above_fresh_count_reports() {
  local root="$1"
  run_floor "$root" fallback-drift-verdict 14338 14000 0 604800 250
  assert_status "$root" 1
  assert_stderr_contains "$root" "is ABOVE a fresh count"
}

# The fallback is meant to lag. A small gap is not news at any age.
case_small_gap_is_tolerated_even_when_old() {
  local root="$1"
  run_floor "$root" fallback-drift-verdict 14338 14400 999999 604800 250
  assert_status "$root" 0
  assert_stdout_contains "$root" "FALLBACK-LAGGING-ACCEPTABLY"
}

# Nor is a large gap that is still fresh: the fallback was updated recently and
# main has simply gained tests since.
case_large_gap_is_tolerated_while_young() {
  local root="$1"
  run_floor "$root" fallback-drift-verdict 14338 20000 60 604800 250
  assert_status "$root" 0
  assert_stdout_contains "$root" "FALLBACK-LAGGING-ACCEPTABLY"
}

# Large AND old together is decay: on a day the cached floor is unavailable,
# this is the number every pull request would be held to.
case_large_and_old_gap_reports() {
  local root="$1"
  run_floor "$root" fallback-drift-verdict 14338 20000 999999 604800 250
  assert_status "$root" 1
  assert_stderr_contains "$root" "has decayed"
  assert_stderr_contains "$root" "would let 5662 deletions through"
}

# Fallback age is measured from the first commit AFTER its last change, so a busy
# branch cannot keep a permanently stale fallback inside any grace window by
# continuously producing young commits.
case_fallback_age_measures_from_the_first_later_commit() {
  local root="$1"
  git -C "$root" init --quiet
  git -C "$root" config --local user.email test@example.com
  git -C "$root" config --local user.name "Floor Self Test"

  printf '100\n' > "$root/.test-baseline"
  git -C "$root" add .test-baseline
  git -C "$root" commit --quiet --no-verify -m "set the fallback"

  run_floor "$root" drift-age-seconds .test-baseline
  assert_status "$root" 0
  [[ "$(cat "$root/stdout.log")" == "0" ]] \
    || fail "a fallback that is the newest change should report zero age, got $(cat "$root/stdout.log")"

  printf 'one\n' > "$root/other.txt"
  git -C "$root" add other.txt
  GIT_COMMITTER_DATE="@$(( $(date -u +%s) - 7200 )) +0000" \
    git -C "$root" commit --quiet --no-verify --date "@$(( $(date -u +%s) - 7200 )) +0000" -m "first commit after the fallback"
  printf 'two\n' > "$root/other.txt"
  git -C "$root" add other.txt
  git -C "$root" commit --quiet --no-verify -m "a much newer commit"

  run_floor "$root" drift-age-seconds .test-baseline
  assert_status "$root" 0
  local age
  age="$(cat "$root/stdout.log")"
  (( age >= 7000 )) || fail "fallback age reset to the newest commit: got ${age}s, expected roughly 7200s"
}

# ── Cross-file pins ─────────────────────────────────────────────────────────

# INVARIANT this case pins: the floor mechanism holds NO write authority. The
# count travels through the Actions cache, which the default token may write with
# no permission grant, so any `write` permission appearing in this workflow means
# something has been added that needs one, and that is the whole class of
# question this design exists to avoid.
case_the_guard_workflow_grants_no_write() {
  local root="$1"
  local writes
  writes="$(grep -cE '^[[:space:]]*[a-z-]+:[[:space:]]*write[[:space:]]*$|^[[:space:]]*permissions:[[:space:]]*write-all' "$GUARD_WORKFLOW" || true)"
  [[ "$writes" == "0" ]] \
    || fail "$GUARD_WORKFLOW declares $writes write permission(s); the floor mechanism needs none"
  [[ -d "$root" ]] || fail "fixture root vanished"
}

# The recorder that committed, pushed a branch, and opened a pull request is
# gone. A future edit that reintroduces any of it also reintroduces the need for
# authority the cache route does not require.
case_nothing_commits_pushes_or_opens_a_pull_request() {
  local root="$1"
  local forbidden
  for forbidden in 'gh pr create' 'gh pr merge' 'git push' 'git commit' 'record-floor:'; do
    if grep -Fq "$forbidden" "$GUARD_WORKFLOW"; then
      fail "$GUARD_WORKFLOW still contains '$forbidden'; the floor is published to a cache, not written to the repository"
    fi
  done
  grep -q 'actions/cache/save@' "$GUARD_WORKFLOW" \
    || fail "$GUARD_WORKFLOW no longer publishes the observed count to a cache"
  grep -q 'actions/cache/restore@' "$GUARD_WORKFLOW" \
    || fail "$GUARD_WORKFLOW no longer restores the published count"
  [[ -d "$root" ]] || fail "fixture root vanished"
}

# The cache key prefix and paths are shared between the publish side, the
# restore side, and this script. A prefix that agrees on only one side is the
# worst failure this design has: the restore misses, the fallback quietly takes
# over, and every check stays green while asserting less.
case_cache_locations_are_not_spelled_out_in_the_workflow() {
  local root="$1"
  local prefix dir
  run_floor "$root" cache-key-prefix
  assert_status "$root" 0
  prefix="$(cat "$root/stdout.log")"
  run_floor "$root" cache-dir
  assert_status "$root" 0
  dir="$(cat "$root/stdout.log")"

  local hits
  hits="$(grep -cF "$prefix" "$GUARD_WORKFLOW" || true)"
  [[ "$hits" == "0" ]] \
    || fail "$GUARD_WORKFLOW spells the cache key prefix out $hits time(s); it must come from cache-key-prefix"
  hits="$(grep -cF "$dir" "$GUARD_WORKFLOW" || true)"
  [[ "$hits" == "0" ]] \
    || fail "$GUARD_WORKFLOW spells the cache directory out $hits time(s); it must come from cache-dir"
  grep -q 'test-baseline-floor\.sh cache-key-prefix' "$GUARD_WORKFLOW" \
    || fail "$GUARD_WORKFLOW does not obtain the cache key prefix from the floor script"
}

# The scheduled backstop watches the committed FALLBACK. If it were repointed at
# something else, a permanently decayed fallback would go unwatched, and it is
# the only thing watching it.
case_the_drift_workflow_watches_the_fallback() {
  local root="$1"
  grep -q 'test-baseline-floor\.sh fallback-drift-verdict' "$DRIFT_WORKFLOW" \
    || fail "$DRIFT_WORKFLOW no longer runs the fallback-decay verdict"
  grep -q 'read-floor \.test-baseline' "$DRIFT_WORKFLOW" \
    || fail "$DRIFT_WORKFLOW no longer reads the committed fallback"
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

run_case "a count below the floor in force reds the pull-request gate" case_below_floor_fails
run_case "a count equal to the floor passes" case_equal_to_floor_passes
run_case "a count above the floor passes and writes nothing" case_above_floor_passes_and_writes_nothing
run_case "a malformed fallback floor is refused, not guessed" case_malformed_floor_refuses
run_case "a leading-zero floor is refused rather than read as octal" case_leading_zero_floor_refuses
run_case "a missing fallback floor is refused" case_missing_floor_refuses
run_case "an unparseable suite summary is refused, never read as passing" case_unparseable_suite_output_refuses
run_case "a cached count above the fallback is the floor" case_cache_hit_above_fallback_wins
run_case "a cached count equal to the fallback is the floor" case_cache_hit_equal_to_fallback
run_case "a cache miss falls back to the committed floor and says so" case_cache_miss_falls_back_and_says_so
run_case "an unreadable cache falls back and says which it was" case_cache_unreadable_falls_back_and_says_which
run_case "a cached count below the fallback never weakens it" case_cache_below_fallback_does_not_weaken_it
run_case "a cached count below the fallback still reds the gate" case_cache_below_fallback_still_reds_the_gate
run_case "the default branch at its tip publishes its count" case_publish_on_main_at_the_tip
run_case "publishing is declined off the default branch" case_publish_declines_off_the_default_branch
run_case "publishing is declined when the branch moved underneath" case_publish_declines_when_the_branch_moved
run_case "the fallback in sync with a fresh count is quiet" case_fallback_in_sync
run_case "a fallback above a fresh count is reported" case_fallback_above_fresh_count_reports
run_case "a small gap is tolerated even when old" case_small_gap_is_tolerated_even_when_old
run_case "a large gap is tolerated while young" case_large_gap_is_tolerated_while_young
run_case "a large and old gap is reported as decay" case_large_and_old_gap_reports
run_case "fallback age is measured from the first later commit" case_fallback_age_measures_from_the_first_later_commit
run_case "the guard workflow grants no write permission" case_the_guard_workflow_grants_no_write
run_case "nothing commits, pushes, or opens a pull request" case_nothing_commits_pushes_or_opens_a_pull_request
run_case "the cache locations are not spelled out in the workflow" case_cache_locations_are_not_spelled_out_in_the_workflow
run_case "the scheduled backstop watches the committed fallback" case_the_drift_workflow_watches_the_fallback

echo "PASS: test-baseline-floor self-tests ($PASSED cases)"
