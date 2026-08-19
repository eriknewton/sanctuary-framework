#!/usr/bin/env bash
# baseline-autocorrect-decision.sh — the ONLY place that decides whether CI may
# write a corrected integer to .test-baseline and push it to a PR branch.
#
# Copyright 2026 Erik Newton
# SPDX-License-Identifier: Apache-2.0
#
# WHY THIS IS A SEPARATE, STANDALONE SCRIPT AND NOT INLINE WORKFLOW YAML: the
# decision has five stated preconditions plus a loop bound and a fork-PR bar,
# all of which must hold before a single byte is written to a file CI can push
# to someone else's branch. Logic with that many branches, buried in a `run:`
# block, cannot be unit-tested — the only way to exercise a YAML conditional is
# to open a real PR and watch what happens. This script takes every input
# explicitly (as flags, never by reading CI-only context like $GITHUB_*) so
# scripts/baseline-autocorrect-decision-self-test.sh can drive it against real
# git fixtures without a network call or a GitHub Actions runner. See that file
# for the required-inputs / conventions this design was asked to mirror:
# scripts/verify-fail-before.sh and its self-test.
#
# Design: Review/Sanctuary/Baseline_Autocorrect_Design_2026-08-19.md (Erik-
# approved 2026-08-19). AGENTS.md's "Commit discipline: test baseline
# enforcement" section is the human-facing summary of what this script decides
# and MUST be kept in sync with the five conditions below (cross-file pin).
#
# CONTRACT WITH THE CALLER (must match .github/workflows/test-baseline-guard.yml):
#   - This script ONLY decides. It never writes .test-baseline, never commits,
#     never pushes. The workflow performs the write/commit/push ONLY when this
#     script prints `DECISION=ACCEPT` and exits 0.
#   - On ACCEPT, stdout carries `NEW_BASELINE=<N>` — the exact integer the
#     workflow must write. The workflow must not derive that number any other
#     way, so there is exactly one place that computed it.
#   - The commit-message format `chore(ci): set .test-baseline to <N>
#     (autocorrect)` is asserted by AUTOCORRECT_COMMIT_RE below and MUST match
#     the format the workflow actually commits with, or the loop-bound check
#     (an autocorrect commit refuses to autocorrect again) silently stops
#     working the moment the two drift apart.
#
# Exit codes: 0 = ACCEPT (safe to write), 1 = REFUSE (fail hard, as today),
# 2 = usage/malformed-input error (a caller bug, not a policy decision).

set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/baseline-autocorrect-decision.sh \
  --gate2a-status <pass|fail> \
  --gate2b-status <pass|fail> \
  --failures <N> \
  --observed-count <N> \
  --base-floor <N> \
  --pr-head-sha <sha> \
  --remote-head-sha <sha> \
  --head-commit-subject <string> \
  --is-fork-pr <true|false>

Prints DECISION=ACCEPT|REFUSE, REASON=<token>, and (on ACCEPT) NEW_BASELINE=<N>
to stdout. Exit 0 on ACCEPT, 1 on REFUSE, 2 on malformed input.
USAGE
}

GATE2A_STATUS=""
GATE2B_STATUS=""
FAILURES=""
OBSERVED_COUNT=""
BASE_FLOOR=""
PR_HEAD_SHA=""
REMOTE_HEAD_SHA=""
HEAD_COMMIT_SUBJECT=""
IS_FORK_PR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gate2a-status) GATE2A_STATUS="${2:-}"; shift 2 ;;
    --gate2b-status) GATE2B_STATUS="${2:-}"; shift 2 ;;
    --failures) FAILURES="${2:-}"; shift 2 ;;
    --observed-count) OBSERVED_COUNT="${2:-}"; shift 2 ;;
    --base-floor) BASE_FLOOR="${2:-}"; shift 2 ;;
    --pr-head-sha) PR_HEAD_SHA="${2:-}"; shift 2 ;;
    --remote-head-sha) REMOTE_HEAD_SHA="${2:-}"; shift 2 ;;
    --head-commit-subject) HEAD_COMMIT_SUBJECT="${2:-}"; shift 2 ;;
    --is-fork-pr) IS_FORK_PR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

# HEAD_COMMIT_SUBJECT is allowed to be an empty string (a commit CAN have an
# empty subject, however rare) so it is intentionally excluded from the
# required-flags loop below; every other flag must be non-empty.
for name in GATE2A_STATUS GATE2B_STATUS FAILURES OBSERVED_COUNT BASE_FLOOR PR_HEAD_SHA REMOTE_HEAD_SHA IS_FORK_PR; do
  if [[ -z "${!name}" ]]; then
    echo "Missing required flag for $name." >&2
    usage
    exit 2
  fi
done

case "$GATE2A_STATUS" in pass|fail) ;; *) echo "--gate2a-status must be pass or fail, got: $GATE2A_STATUS" >&2; exit 2 ;; esac
case "$GATE2B_STATUS" in pass|fail) ;; *) echo "--gate2b-status must be pass or fail, got: $GATE2B_STATUS" >&2; exit 2 ;; esac
case "$IS_FORK_PR" in true|false) ;; *) echo "--is-fork-pr must be true or false, got: $IS_FORK_PR" >&2; exit 2 ;; esac
# Portable lowercasing (`${var,,}` is bash-4+ only; this repo's contributors
# and CI both run scripts that must also work under macOS's stock bash 3.2).
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

for pair in "FAILURES:$FAILURES" "OBSERVED_COUNT:$OBSERVED_COUNT" "BASE_FLOOR:$BASE_FLOOR"; do
  flag_name="${pair%%:*}"
  flag_value="${pair#*:}"
  if ! [[ "$flag_value" =~ ^[0-9]+$ ]]; then
    echo "--$(lower "$flag_name") must be a non-negative integer, got: $flag_value" >&2
    exit 2
  fi
done
if ! [[ "$PR_HEAD_SHA" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
  echo "--pr-head-sha must look like a git SHA, got: $PR_HEAD_SHA" >&2
  exit 2
fi
if ! [[ "$REMOTE_HEAD_SHA" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
  echo "--remote-head-sha must look like a git SHA, got: $REMOTE_HEAD_SHA" >&2
  exit 2
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Must match the commit message this script's caller (the workflow) actually
# writes on ACCEPT. See the CONTRACT comment at the top of this file.
AUTOCORRECT_COMMIT_RE='^chore\(ci\): set \.test-baseline to [0-9]+ \(autocorrect\)$'

refuse() {
  local reason="$1"
  shift
  echo "DECISION=REFUSE"
  echo "REASON=$reason"
  echo "observed_count=$OBSERVED_COUNT base_floor=$BASE_FLOOR"
  if [[ $# -gt 0 ]]; then
    echo "$*"
  fi
  exit 1
}

# --- Fork-PR bar. Checked before anything else: a fork PR gets no write
# access considered at all, regardless of how clean the rest of the run is.
# INVARIANT: this prevents a forked contributor's PR from ever causing this
# repo's CI token to push a commit to a branch this repo does not own the
# write path for. The workflow-level trigger (`pull_request`, not
# `pull_request_target`) already denies the CI token secrets on fork PRs in
# practice; this is the second, script-level bar so the refusal is provable
# in a unit test rather than resting on GitHub's event-permission model alone.
if [[ "$IS_FORK_PR" == "true" ]]; then
  refuse "FORK_PR" "Fork PRs never get an autocorrect push; fix .test-baseline by hand. observed_count=$OBSERVED_COUNT base_floor=$BASE_FLOOR"
fi

# --- Loop bound. If the PR's actual head commit (never the checkout's HEAD —
# see the note below) is itself an autocorrect commit, refuse rather than
# correct again.
# INVARIANT: without this, a second wrong guess after the first autocorrect
# (or a flaky count) could re-trigger CI into an unbounded push loop. One
# correction per head, then a hard failure that prints the number so a human
# takes over.
#
# WHY --head-commit-subject IS A FLAG AND NOT `git log -1 --format=%s HEAD`:
# actions/checkout on a `pull_request` event checks out the synthetic merge
# commit (refs/pull/N/merge) by default, so the repo's actual HEAD there is a
# GitHub-generated "Merge <sha> into <sha>" commit, never the PR's own last
# commit. Reading HEAD's subject in that checkout would never match
# AUTOCORRECT_COMMIT_RE even immediately after an autocorrect, silently
# disabling the loop bound. The caller must resolve the PR's real head commit
# subject itself (e.g. `git log -1 --format=%s <pr-head-sha>`) and pass it
# here explicitly.
if [[ "$HEAD_COMMIT_SUBJECT" =~ $AUTOCORRECT_COMMIT_RE ]]; then
  refuse "HEAD_IS_AUTOCORRECT_COMMIT" "The PR's head commit ($HEAD_COMMIT_SUBJECT) is already an autocorrect commit; refusing a second correction on the same head. observed_count=$OBSERVED_COUNT base_floor=$BASE_FLOOR"
fi

# --- Condition 1: gate 2a (transform/collection errors) passed.
# INVARIANT: this failure class means the suite did not genuinely run to
# completion. The passing count in that state is not evidence of anything;
# writing it to .test-baseline would launder a broken run into a green floor.
if [[ "$GATE2A_STATUS" != "pass" ]]; then
  refuse "GATE_2A_FAILED" "Gate 2a (transform/collection error detection) did not pass; this is not the integer-only case."
fi

# --- Condition 2: gate 2b (silent test-file drop) passed.
# INVARIANT: a passing count computed while a test file failed to load is a
# count over a SMALLER suite than the one .test-baseline is supposed to floor.
# Autocorrecting here would silently lower real coverage disguised as a normal
# baseline bump.
if [[ "$GATE2B_STATUS" != "pass" ]]; then
  refuse "GATE_2B_FAILED" "Gate 2b (silent test-file drop detection) did not pass; this is not the integer-only case."
fi

# --- Condition 3: zero test failures in the run.
# INVARIANT: a failing test is a commit-blocker on its own merits. Autocorrect
# exists to stop asking humans to guess an integer, never to paper over a red
# test by moving the floor.
if [[ "$FAILURES" != "0" ]]; then
  refuse "TEST_FAILURES_PRESENT" "$FAILURES failing test(s) in this run; this is not the integer-only case."
fi

# --- Condition 4: observed count is STRICTLY GREATER than the BASE branch's
# .test-baseline (never the PR's own, possibly-already-wrong, committed value).
# INVARIANT: a count at or below the base floor is a REGRESSION, not a drift
# that needs bumping upward. Autocorrecting here would write a floor that is
# lower than or equal to what main already guarantees, which is exactly the
# stale-floor-lets-a-later-loss-hide-in-the-gap failure the guard exists to
# prevent. This must never auto-fire; a human writes the scoped `-N` commit.
if (( OBSERVED_COUNT <= BASE_FLOOR )); then
  refuse "COUNT_AT_OR_BELOW_FLOOR" "observed count $OBSERVED_COUNT is at or below the base floor $BASE_FLOOR; this is a regression candidate, not a drift. Fix the regression, or if tests were deliberately deleted, lower .test-baseline by hand with a scoped -N commit and its written justification."
fi

# --- Condition 5a: the PR head SHA this job started against is still the
# branch's current tip (no race with a concurrent push landing mid-run).
# INVARIANT: without this, a push that lands on the PR branch WHILE this job
# is running could have its own commits silently overwritten by an autocorrect
# commit built on a stale checkout, or the autocorrect could be appended after
# a human already fixed the same thing, doubling the correction.
#
# WHY BOTH SIDES ARE FLAGS AND NEITHER IS READ FROM THE LOCAL CHECKOUT: for
# the same reason as the loop-bound check above, the checkout's `git rev-parse
# HEAD` is the synthetic merge commit's SHA on a `pull_request` trigger, not
# the PR branch's tip, so it can never equal a real head SHA and would refuse
# on every single run. The caller supplies PR_HEAD_SHA (the tip it believed
# when the job started, e.g. the triggering event's head SHA) and
# REMOTE_HEAD_SHA (a fresh `git ls-remote`/API read of the branch's tip taken
# immediately before this decision), so the comparison is between two values
# that actually describe the same thing at two points in time.
if [[ "$PR_HEAD_SHA" != "$REMOTE_HEAD_SHA" ]]; then
  refuse "HEAD_SHA_MISMATCH" "the branch's current tip ($REMOTE_HEAD_SHA) does not match the head this run started against ($PR_HEAD_SHA); a concurrent push is the likely cause. Re-run once the branch settles."
fi

# --- Condition 5b: the write this script is about to authorize would touch
# only .test-baseline. Checked as "is the working tree already clean" — if it
# is, then the one edit the workflow is about to make (rewriting the single
# line in .test-baseline) is, by construction, the only change in the commit.
# INVARIANT: this is the mechanical bound the design's risk section relies on
# ("the autocorrect commit is mechanically bounded to one file and one
# integer"). A dirty tree at this point means something else in the job left
# stray changes behind, and sweeping those into a commit attributed to
# `github-actions[bot]` and pushed to someone else's branch is the failure
# this condition exists to prevent, independent of how it happened.
DIRTY_STATUS="$(git status --porcelain)"
if [[ -n "$DIRTY_STATUS" ]]; then
  refuse "DIFF_NOT_BASELINE_ONLY" "working tree has changes beyond a bare .test-baseline edit before the write; refusing rather than sweeping unrelated changes into the autocorrect commit.
$DIRTY_STATUS"
fi

echo "DECISION=ACCEPT"
echo "REASON=ACCEPT"
echo "NEW_BASELINE=$OBSERVED_COUNT"
echo "observed_count=$OBSERVED_COUNT base_floor=$BASE_FLOOR"
exit 0
