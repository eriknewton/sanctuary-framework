#!/usr/bin/env bash
# baseline-autocorrect-decision-self-test.sh — proves each refusal path in
# scripts/baseline-autocorrect-decision.sh actually refuses, and refuses for
# the reason it claims to, not merely that it refuses. Shape and fixture
# conventions (disposable git repos, GIT_ENV_KEYS isolation, run_case /
# assert_* helpers) mirror scripts/verify-fail-before-self-test.sh.
#
# Deliberately avoids bash-4+-only features (associative arrays, namerefs,
# `${var,,}`): this file, like the script it tests, is exercised locally on
# macOS's stock bash 3.2 as well as CI's newer bash, per the repo's baseline-
# floor rule that macOS local is not a stand-in for CI but IS where this
# script gets run by hand before a PR opens.
#
# For the two conditions that depend on real git state (the regression floor
# and the dirty-tree bound), the divergence is PLANTED in a real git fixture
# and the script is proven to refuse on it, per the standing rule that an
# unproven guard is not evidence.
#
# Each case gets a fixture ROOT with the git repo one level down, at
# $ROOT/repo, never at $ROOT itself. run_decision writes stdout.log,
# stderr.log, and status into $ROOT (outside the repo). Redirecting a shell
# command's stdout to a file creates that file before the command runs, so
# writing logs inside the repo would leave freshly-truncated, untracked log
# files sitting in the working tree the instant the decision script's own
# `git status --porcelain` check ran — a self-inflicted false
# DIFF_NOT_BASELINE_ONLY on every single case. Keeping logs outside the repo
# is what lets the dirty-tree case's PLANTED divergence be the only untracked
# file the script ever sees.
#
# Copyright 2026 Erik Newton
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DECISION_SCRIPT="$SCRIPT_DIR/baseline-autocorrect-decision.sh"

GIT_ENV_KEYS=(
  GIT_DIR
  GIT_COMMON_DIR
  GIT_WORK_TREE
  GIT_INDEX_FILE
  GIT_OBJECT_DIRECTORY
  GIT_ALTERNATE_OBJECT_DIRECTORIES
  GIT_NAMESPACE
  GIT_PREFIX
)

clean_git() (
  for key in "${GIT_ENV_KEYS[@]}"; do
    unset "$key"
  done
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_CONFIG_SYSTEM=/dev/null
  git -C "$@"
)

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

write_file() {
  local repo="$1"
  local rel="$2"
  local body="$3"
  local path="$repo/$rel"
  mkdir -p "$(dirname "$path")"
  printf '%s' "$body" > "$path"
}

commit_all() {
  local repo="$1"
  local message="$2"
  clean_git "$repo" add .
  clean_git "$repo" commit --quiet -m "$message" --no-verify
}

# A minimal fixture repo: one commit, one tracked file, so "the working tree
# is clean" and "HEAD is a normal commit" both hold by construction until a
# case deliberately disturbs one of them.
setup_fixture() {
  local repo="$1"
  mkdir -p "$repo"
  clean_git "$repo" init --quiet
  local top
  top="$(clean_git "$repo" rev-parse --show-toplevel)"
  local repo_real
  local top_real
  repo_real="$(cd "$repo" && pwd -P)"
  top_real="$(cd "$top" && pwd -P)"
  [[ "$top_real" == "$repo_real" ]] || fail "temp git repo escaped fixture repo dir"

  clean_git "$repo" config --local user.email test@example.com
  clean_git "$repo" config --local user.name "Baseline Autocorrect Test"
  write_file "$repo" ".test-baseline" "100
"
  commit_all "$repo" "base commit"
}

head_sha() {
  local repo="$1"
  clean_git "$repo" rev-parse HEAD
}

# Populates the global ARGS array with a full flag set. Positional, not a
# name=value map, so this file needs neither associative arrays nor namerefs
# (both bash-4+ only) to let each case override just the flag it is testing.
# head-commit-subject and remote-head-sha are read from the fixture's actual
# HEAD by default_args below (see its comment for why they must be supplied
# explicitly rather than read from the checkout inside the decision script).
make_args() {
  ARGS=(
    --gate2a-status "$1"
    --gate2b-status "$2"
    --failures "$3"
    --observed-count "$4"
    --base-floor "$5"
    --pr-head-sha "$6"
    --remote-head-sha "$7"
    --head-commit-subject "$8"
    --is-fork-pr "$9"
  )
}

# The "everything is fine" defaults: gates pass, no failures, 142 observed
# against a base floor of 100 (comfortably above), PR head SHA equal to the
# remote's (no race), the fixture's real commit subject (never an autocorrect
# message), not a fork.
default_args() {
  local repo="$1"
  local head
  local subject
  head="$(head_sha "$repo")"
  subject="$(clean_git "$repo" log -1 --format=%s)"
  make_args pass pass 0 142 100 "$head" "$head" "$subject" false
}

# Runs the decision script against the fixture repo with the same git-env
# isolation the fixture itself uses, so a stray host gitconfig cannot change
# decision output. Logs land in $root (the fixture's PARENT), never in the
# repo — see the file header for why that matters.
run_decision() {
  local root="$1"
  local repo="$2"
  shift 2
  set +e
  (
    for key in "${GIT_ENV_KEYS[@]}"; do
      unset "$key"
    done
    export GIT_CONFIG_GLOBAL=/dev/null
    export GIT_CONFIG_SYSTEM=/dev/null
    cd "$repo"
    bash "$DECISION_SCRIPT" "$@"
  ) > "$root/stdout.log" 2> "$root/stderr.log"
  local status=$?
  set -e
  printf '%s\n' "$status" > "$root/status"
}

assert_status() {
  local root="$1"
  local expected="$2"
  local actual
  actual="$(cat "$root/status")"
  [[ "$actual" == "$expected" ]] || fail "expected status $expected, got $actual
stdout:
$(cat "$root/stdout.log")
stderr:
$(cat "$root/stderr.log")"
}

assert_reason() {
  local root="$1"
  local expected="$2"
  grep -Fq "REASON=$expected" "$root/stdout.log" || fail "expected REASON=$expected, not found
stdout:
$(cat "$root/stdout.log")"
}

assert_contains() {
  local root="$1"
  local rel="$2"
  local needle="$3"
  grep -Fq -- "$needle" "$root/$rel" || fail "$rel did not contain: $needle
contents:
$(cat "$root/$rel" 2>/dev/null || true)"
}

run_case() {
  local name="$1"
  local fn="$2"
  local root
  root="$(mktemp -d "${TMPDIR:-/tmp}/sanctuary-baseline-autocorrect.XXXXXX")"
  "$fn" "$root"
  rm -rf "$root"
  echo "PASS: $name"
}

# --- Malformed-input cases: the script's own usage guard, exit 2. ---------

case_missing_flag_is_usage_error() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  run_decision "$root" "$repo" --gate2a-status pass
  assert_status "$root" 2
  assert_contains "$root" stderr.log "Missing required flag"
}

case_bad_status_value_is_usage_error() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  local head
  head="$(head_sha "$repo")"
  make_args maybe pass 0 142 100 "$head" "$head" "base commit" false
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 2
  assert_contains "$root" stderr.log "--gate2a-status must be pass or fail"
}

# --- The five stated preconditions, each proven to refuse with its own
# token, plus the loop bound and the fork bar. ------------------------------

case_gate2a_fail_refuses() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  local head
  head="$(head_sha "$repo")"
  make_args fail pass 0 142 100 "$head" "$head" "base commit" false
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "GATE_2A_FAILED"
}

case_gate2b_fail_refuses() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  local head
  head="$(head_sha "$repo")"
  make_args pass fail 0 142 100 "$head" "$head" "base commit" false
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "GATE_2B_FAILED"
}

case_test_failure_present_refuses() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  local head
  head="$(head_sha "$repo")"
  make_args pass pass 3 142 100 "$head" "$head" "base commit" false
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "TEST_FAILURES_PRESENT"
}

# PLANTED DIVERGENCE: the base floor is 100. This case sets observed-count to
# exactly that floor — a genuine regression candidate, since condition 4
# requires STRICT excess over the base floor, not "at least". Proves the
# script refuses rather than treating "unchanged" as "fine to leave alone".
case_count_equal_to_floor_refuses() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  local head
  head="$(head_sha "$repo")"
  make_args pass pass 0 100 100 "$head" "$head" "base commit" false
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "COUNT_AT_OR_BELOW_FLOOR"
}

# PLANTED DIVERGENCE, the sharper case: observed-count is BELOW the base
# floor, i.e. a real test-count regression. Proves the script refuses this the
# same way as the boundary case, not only the tie.
case_count_below_floor_refuses() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  local head
  head="$(head_sha "$repo")"
  make_args pass pass 0 97 100 "$head" "$head" "base commit" false
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "COUNT_AT_OR_BELOW_FLOOR"
  assert_contains "$root" stdout.log "regression candidate"
}

# PLANTED DIVERGENCE, the realistic form of the race: the branch actually
# moves after this run's PR_HEAD_SHA was captured (a real second commit lands,
# just as a concurrent human push would), and REMOTE_HEAD_SHA (what a fresh
# `git ls-remote` would read right now) reflects the NEW tip. Proves the
# script refuses on the real shape of the race, not a synthetic mismatched
# string that could never occur in practice.
case_head_sha_mismatch_refuses() {
  local root="$1"
  local repo="$root/repo"
  local original_head
  local moved_head
  setup_fixture "$repo"
  original_head="$(head_sha "$repo")"
  write_file "$repo" ".test-baseline" "101
"
  commit_all "$repo" "a concurrent push lands mid-run"
  moved_head="$(head_sha "$repo")"
  make_args pass pass 0 142 100 "$original_head" "$moved_head" "a concurrent push lands mid-run" false
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "HEAD_SHA_MISMATCH"
}

# Dirty tree beyond .test-baseline: something other than the pending edit is
# already modified when the decision runs. Refuses rather than sweeping it
# into the autocorrect commit.
case_dirty_tree_refuses() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  write_file "$repo" "server/src/unrelated.ts" "export const x = 1;
"
  default_args "$repo"
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "DIFF_NOT_BASELINE_ONLY"
}

case_fork_pr_refuses() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  local head
  head="$(head_sha "$repo")"
  make_args pass pass 0 142 100 "$head" "$head" "base commit" true
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "FORK_PR"
}

# Loop bound: HEAD is itself an autocorrect commit. This commit message format
# MUST match AUTOCORRECT_COMMIT_RE in the decision script and the format the
# real workflow commits with — this case is also the regression guard for
# that three-way agreement (script regex / this fixture / the workflow step).
case_head_already_autocorrect_refuses() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  write_file "$repo" ".test-baseline" "142
"
  commit_all "$repo" "chore(ci): set .test-baseline to 142 (autocorrect)"
  default_args "$repo"
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 1
  assert_reason "$root" "HEAD_IS_AUTOCORRECT_COMMIT"
}

# --- The accept path. -------------------------------------------------------

case_happy_path_accepts() {
  local root="$1"
  local repo="$root/repo"
  setup_fixture "$repo"
  default_args "$repo"
  run_decision "$root" "$repo" "${ARGS[@]}"
  assert_status "$root" 0
  assert_reason "$root" "ACCEPT"
  assert_contains "$root" stdout.log "NEW_BASELINE=142"
}

run_case "missing flag is a usage error (exit 2)" case_missing_flag_is_usage_error
run_case "bad enum value is a usage error (exit 2)" case_bad_status_value_is_usage_error
run_case "gate 2a failure refuses with GATE_2A_FAILED" case_gate2a_fail_refuses
run_case "gate 2b failure refuses with GATE_2B_FAILED" case_gate2b_fail_refuses
run_case "a present test failure refuses with TEST_FAILURES_PRESENT" case_test_failure_present_refuses
run_case "observed count equal to the base floor refuses (planted tie)" case_count_equal_to_floor_refuses
run_case "observed count below the base floor refuses (planted regression)" case_count_below_floor_refuses
run_case "a head SHA mismatch refuses with HEAD_SHA_MISMATCH" case_head_sha_mismatch_refuses
run_case "a dirty tree beyond .test-baseline refuses with DIFF_NOT_BASELINE_ONLY" case_dirty_tree_refuses
run_case "a fork PR refuses with FORK_PR" case_fork_pr_refuses
run_case "HEAD already an autocorrect commit refuses (loop bound)" case_head_already_autocorrect_refuses
run_case "the fully-clean happy path accepts and prints NEW_BASELINE" case_happy_path_accepts

echo "PASS: baseline-autocorrect-decision self-tests"
