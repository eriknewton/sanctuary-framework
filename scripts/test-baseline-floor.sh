#!/usr/bin/env bash
#
# Sanctuary .test-baseline floor decision logic
# Copyright 2026 Erik Newton
# SPDX-License-Identifier: Apache-2.0
#
# Every decision the test-baseline floor mechanism makes lives here, as a
# subcommand with an exit code, so the whole mechanism is exercisable without a
# CI runner. The workflow at .github/workflows/test-baseline-guard.yml and the
# scheduled drift check at .github/workflows/test-baseline-floor-drift.yml call
# these subcommands and do the I/O the runner has to do (running the suite,
# committing, pushing); they contain no comparison of their own.
#
# Why the logic is not inline in the YAML: an earlier attempt at this mechanism
# put its decisions in workflow steps, where the only way to exercise a branch
# was to merge it and watch. The self-test at
# scripts/test-baseline-floor-self-test.sh is this file's only reason to be a
# separate script.
#
# THE SHAPE OF THE RULE (see AGENTS.md, "Commit discipline"):
#
#   On a pull request  the observed passing count must not be BELOW the floor
#                      committed at the repo root. A count above the floor is
#                      normal and passes. Nothing writes the floor.
#   On main, on push   the observed count is RECORDED into .test-baseline when
#                      it differs, by the CI actor, one file, one commit.
#
# Exit codes, uniform across subcommands:
#   0   the checked condition holds / proceed
#   1   the checked condition fails / refuse
#   2   usage error, or an input this script will not interpret (fail closed)
#   10  no action needed (record-decision only: the floor is already correct)
#
# A note on failing closed: every parse below refuses rather than guessing. An
# unreadable floor or an unparseable suite summary must not read as "no
# regression"; that conflation is the failure class this whole guard exists for.

set -euo pipefail

# Exit code for "the floor is already what it should be, do nothing". Distinct
# from 0 so a caller cannot read "no work to do" as "work done".
readonly EXIT_NO_ACTION=10

# The canonical recorded-floor commit subject, in printf form. It is BOTH the
# message the record step writes AND the pattern the loop bound recognizes, and
# it is defined once here so those two can never drift into a loop where the
# recorder does not recognize its own commits.
#
# Must match the commit step in .github/workflows/test-baseline-guard.yml, which
# obtains the subject by calling `commit-subject` rather than spelling it out.
readonly FLOOR_COMMIT_SUBJECT_FORMAT='chore(ci): record .test-baseline %s after merge'

# The one branch this mechanism may ever write. Must match the `if:` on the
# record-floor job in .github/workflows/test-baseline-guard.yml, which gates on
# the same ref before the job is even created.
readonly FLOOR_BRANCH_REF='refs/heads/main'

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/test-baseline-floor.sh <subcommand> [args]

  read-floor <floor-file>
      Print the committed floor integer. Exit 2 if missing or malformed.

  parse-count <vitest-log>
      Print the passing-test count parsed from a captured vitest run.
      Exit 2 if the summary line is absent or not a plain integer.

  assert-not-below <floor> <observed>
      The pull-request gate. Exit 0 when observed >= floor, 1 when below.

  record-decision <floor> <observed>
      Exit 0 when the floor must be rewritten to <observed>, 10 when it is
      already correct.

  record <floor-file> <observed>
      Write <observed> into <floor-file>. Exit 10 without touching the file
      when it already holds that value.

  commit-subject <n>
      Print the canonical recorded-floor commit subject for count <n>.

  guard-record-context <ref> <head-subject>
      Exit 0 when it is safe to record a floor in this context, 1 with a
      reason otherwise (wrong branch, or the head commit is one of ours).

  drift-age-seconds <floor-file>
      Print how many seconds the tree has moved without the floor being
      rewritten: now minus the commit date of the first commit that followed
      the floor's last change. Prints 0 when the floor is the newest change.

  drift-verdict <floor> <observed> <age-seconds> <window-seconds>
      The scheduled backstop. Exit 0 when in sync, or when drift is younger
      than the window (a record job may still be in flight). Exit 1 when
      drift has outlived the window.
USAGE
}

die_usage() {
  echo "$1" >&2
  usage
  exit 2
}

# INVARIANT: a counter is accepted only in canonical decimal form, because every
# comparison below is arithmetic. A leading-zero string such as "007" is parsed
# as octal by `(( ))` and would silently compare as 7; a value with any other
# character would evaluate as 0 and read as "no regression", which is the
# absent-reads-as-passing conflation this guard exists to prevent.
is_canonical_count() {
  [[ "$1" =~ ^(0|[1-9][0-9]*)$ ]]
}

require_count() {
  local label="$1"
  local value="$2"
  if ! is_canonical_count "$value"; then
    echo "FAIL: $label must be a plain non-negative integer, got: '$value'" >&2
    exit 2
  fi
}

cmd_read_floor() {
  local floor_file="${1:-}"
  [[ -n "$floor_file" ]] || die_usage "read-floor needs a floor file path."
  if [[ ! -f "$floor_file" ]]; then
    echo "FAIL: $floor_file is missing. It must exist and hold a single integer, the recorded passing count on main." >&2
    exit 2
  fi
  local raw
  raw="$(tr -d '[:space:]' < "$floor_file")"
  require_count "$floor_file" "$raw"
  printf '%s\n' "$raw"
}

# The single parser for vitest's passing count. Both the pull-request gate and
# the recorder read the suite through this function, so the number the gate
# compares and the number the recorder writes cannot come from two regexes that
# drift. Real vitest summary line, ANSI stripped by NO_COLOR in the workflow:
#
#      Tests  2 passed (2)
#
# The parenthesised total counts collected tests including skipped ones; the
# floor tracks tests that actually PASSED, so the first number is the one read.
cmd_parse_count() {
  local log="${1:-}"
  [[ -n "$log" ]] || die_usage "parse-count needs a captured vitest log path."
  if [[ ! -f "$log" ]]; then
    echo "FAIL: vitest log not found at $log." >&2
    exit 2
  fi
  local matched=""
  matched="$(grep -oE "Tests[[:space:]]+[0-9]+ passed" "$log" | grep -oE "[0-9]+" | head -1 || true)"
  if [[ -z "$matched" ]]; then
    echo "FAIL: could not parse a passing-test count from $log. Refusing rather than assuming zero regression." >&2
    exit 2
  fi
  require_count "parsed passing count" "$matched"
  printf '%s\n' "$matched"
}

# INVARIANT: the pull-request side asserts a FLOOR and nothing else. It does not
# demand equality and does not ask the author to record anything, because under
# this design the recorded value is produced on main after the merge. Demanding
# equality here is what forced every PR to guess an integer computed on a
# platform the author cannot run.
cmd_assert_not_below() {
  local floor="${1:-}"
  local observed="${2:-}"
  [[ -n "$floor" && -n "$observed" ]] || die_usage "assert-not-below needs <floor> <observed>."
  require_count "floor" "$floor"
  require_count "observed count" "$observed"

  if (( observed < floor )); then
    echo "FAIL: test baseline regression. Recorded floor on main: $floor. Observed passing: $observed. Missing $((floor - observed)) tests." >&2
    echo "  Restore the tests, or lower the floor deliberately in this pull request with a written justification (see AGENTS.md)." >&2
    exit 1
  fi
  if (( observed > floor )); then
    echo "OK: $observed passing, $((observed - floor)) above the recorded floor of $floor. The floor is recorded on main after this merges."
    exit 0
  fi
  echo "OK: $observed passing, exactly at the recorded floor."
}

cmd_record_decision() {
  local floor="${1:-}"
  local observed="${2:-}"
  [[ -n "$floor" && -n "$observed" ]] || die_usage "record-decision needs <floor> <observed>."
  require_count "floor" "$floor"
  require_count "observed count" "$observed"

  if [[ "$floor" == "$observed" ]]; then
    echo "unchanged: the recorded floor is already $floor."
    exit "$EXIT_NO_ACTION"
  fi
  echo "record: $floor -> $observed"
}

# INVARIANT: the recorded value is whatever the suite counted on main, in both
# directions. It is not clamped upward. A deliberate test removal that a
# reviewer approved lands here as a lower recorded floor, which is the point:
# the floor describes main, it does not argue with it.
cmd_record() {
  local floor_file="${1:-}"
  local observed="${2:-}"
  [[ -n "$floor_file" && -n "$observed" ]] || die_usage "record needs <floor-file> <observed>."
  require_count "observed count" "$observed"

  local current=""
  if [[ -f "$floor_file" ]]; then
    current="$(tr -d '[:space:]' < "$floor_file")"
  fi
  if [[ "$current" == "$observed" ]]; then
    echo "unchanged: $floor_file already holds $observed; not writing."
    exit "$EXIT_NO_ACTION"
  fi
  printf '%s\n' "$observed" > "$floor_file"
  echo "recorded: $floor_file now holds $observed (was '${current:-absent}')."
}

cmd_commit_subject() {
  local count="${1:-}"
  [[ -n "$count" ]] || die_usage "commit-subject needs a count."
  require_count "count" "$count"
  # shellcheck disable=SC2059
  printf "$FLOOR_COMMIT_SUBJECT_FORMAT\\n" "$count"
}

# INVARIANT: the recorder must not observe its own commit, or every recorded
# floor would push a commit that triggers another run that pushes another
# commit. Two independent bounds hold that closed and both are self-tested:
# this refusal on the subject, and record-decision returning "no action" because
# the value it would write is the value already there. The subject is generated
# by cmd_commit_subject, so the writer and the recognizer are one string.
#
# BOUND, stated rather than implied: a human squash-merge titled exactly like a
# recorded-floor commit makes this refuse for that one merge, leaving the floor
# stale by one merge. The next merge records it, and the scheduled drift check
# is the backstop if there is no next merge.
cmd_guard_record_context() {
  local ref="${1:-}"
  local head_subject="${2-}"
  [[ -n "$ref" ]] || die_usage "guard-record-context needs <ref> <head-subject>."

  if [[ "$ref" != "$FLOOR_BRANCH_REF" ]]; then
    echo "REFUSE: the floor is recorded on $FLOOR_BRANCH_REF only, and this ran on '$ref'." >&2
    exit 1
  fi

  local own_subject_prefix="${FLOOR_COMMIT_SUBJECT_FORMAT%%%s*}"
  local own_subject_suffix="${FLOOR_COMMIT_SUBJECT_FORMAT##*%s}"
  if [[ "$head_subject" == "$own_subject_prefix"*"$own_subject_suffix" ]]; then
    echo "REFUSE: the head commit is a recorded-floor commit ('$head_subject'); recording again would loop." >&2
    exit 1
  fi

  echo "OK: recording is permitted on $ref."
}

# How long the tree has moved on without the floor being rewritten. Measured
# from the FIRST commit that followed the floor's last change, not from the
# newest commit, because a busy branch keeps the newest commit young forever and
# would keep persistent drift permanently inside any grace window.
#
# Failure mode note for whoever reads this at 2am: a shallow clone has no such
# history and this returns 0, which reads as "no drift", so the workflow that
# calls it checks out with full history. A truncated history looks exactly like
# a healthy floor from here.
cmd_drift_age_seconds() {
  local floor_file="${1:-}"
  [[ -n "$floor_file" ]] || die_usage "drift-age-seconds needs a floor file path."

  local floor_commit=""
  floor_commit="$(git log -1 --format=%H -- "$floor_file" 2>/dev/null || true)"
  if [[ -z "$floor_commit" ]]; then
    # The floor has no commit touching it in the visible history. There is no
    # honest age to report, so report none rather than inventing a large one.
    printf '0\n'
    return 0
  fi

  local first_after=""
  first_after="$(git log --reverse --format=%ct "$floor_commit"..HEAD 2>/dev/null | head -1 || true)"
  if [[ -z "$first_after" ]]; then
    printf '0\n'
    return 0
  fi

  local now
  now="$(date -u +%s)"
  local age=$(( now - first_after ))
  if (( age < 0 )); then
    age=0
  fi
  printf '%s\n' "$age"
}

# INVARIANT: this check is a BACKSTOP, not the primary alarm. The primary alarm
# is the record job failing on main, which reds a push to main and is visible
# immediately. This exists for the case that alarm cannot cover: a record job
# that never ran at all, which produces no failed run to notice.
#
# BOUND: drift younger than the window is deliberately not reported, so a record
# job in flight does not page anyone. That grace is also this check's limit.
cmd_drift_verdict() {
  local floor="${1:-}"
  local observed="${2:-}"
  local age="${3:-}"
  local window="${4:-}"
  [[ -n "$floor" && -n "$observed" && -n "$age" && -n "$window" ]] \
    || die_usage "drift-verdict needs <floor> <observed> <age-seconds> <window-seconds>."
  require_count "floor" "$floor"
  require_count "observed count" "$observed"
  require_count "drift age in seconds" "$age"
  require_count "drift window in seconds" "$window"

  if [[ "$floor" == "$observed" ]]; then
    echo "IN-SYNC: the recorded floor and a fresh count both read $floor."
    return 0
  fi

  if (( age < window )); then
    echo "DRIFT-WITHIN-WINDOW: recorded floor $floor, fresh count $observed, drift ${age}s old, window ${window}s. A record job may still be in flight; not reporting yet."
    return 0
  fi

  echo "FAIL: the recorded floor has been stale for ${age}s, past the ${window}s window. Recorded floor: $floor. Fresh count: $observed." >&2
  echo "  A stale floor is indistinguishable from a healthy one on a pull request: the gate still passes, it simply asserts less than it should." >&2
  echo "  Find the record job that failed or never ran on a push to main, and re-run it." >&2
  exit 1
}

main() {
  local subcommand="${1:-}"
  if [[ -z "$subcommand" ]]; then
    usage
    exit 2
  fi
  shift

  case "$subcommand" in
    read-floor)           cmd_read_floor "$@" ;;
    parse-count)          cmd_parse_count "$@" ;;
    assert-not-below)     cmd_assert_not_below "$@" ;;
    record-decision)      cmd_record_decision "$@" ;;
    record)               cmd_record "$@" ;;
    commit-subject)       cmd_commit_subject "$@" ;;
    guard-record-context) cmd_guard_record_context "$@" ;;
    drift-age-seconds)    cmd_drift_age_seconds "$@" ;;
    drift-verdict)        cmd_drift_verdict "$@" ;;
    -h|--help|help)       usage; exit 0 ;;
    *)                    die_usage "Unknown subcommand: $subcommand" ;;
  esac
}

main "$@"
