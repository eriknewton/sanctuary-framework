#!/usr/bin/env bash
# Generic bounded-retry wrapper for CI network-dependent commands
# (apt-get, pip install, ...). It exists because of a measured incident,
# not a hypothetical: on 2026-08-19 the unbounded `apt-get` step in
# .github/actions/setup-linux-secret-service/action.yml hung across FOUR
# separate PRs (2.5h, 40+min, ~80min across three jobs, and once until
# GitHub itself reaped the dead runners), because a stalled package
# mirror had no timeout or retry to bound it. Route every network install
# step through this script instead of calling the package manager
# directly.
#
# Usage: retry-with-timeout.sh <label> -- <command> [args...]
#
# Env overrides (used by the self-test in
# scripts/retry-with-timeout-self-test.sh to exercise every path -- first-try
# success, retry-then-success, exhausted retries, and a real timeout, with
# and without a `timeout`/`gtimeout` binary present -- in seconds instead of
# minutes; production call sites should leave these at their defaults):
#   RETRY_ATTEMPT_TIMEOUT_S, RETRY_MAX_ATTEMPTS, RETRY_BACKOFF_S
#
# Failure mode: if a step wrapped by this script goes red FAST with exit
# 124 in the log, the command timed out on every attempt -- a mirror or
# network stall, and rerunning the job is the right (now-fallback, not
# primary) response. If it goes red fast with the SAME non-124 exit code
# repeated on every attempt line, that is the wrapped command itself
# refusing (bad package name, broken dependency, wrong hash) -- retrying
# already proved that further retries will not help, so treat it as a
# real failure and fix the command, not the network.
set -u
set -o pipefail

usage() {
  echo "usage: retry-with-timeout.sh <label> -- <command> [args...]" >&2
}

if [ "$#" -lt 2 ]; then
  usage
  exit 64
fi

label="$1"
shift
if [ "$1" != "--" ]; then
  usage
  exit 64
fi
shift

if [ "$#" -eq 0 ]; then
  echo "retry-with-timeout: [$label] no command given" >&2
  exit 64
fi

# Derivation for the three defaults below (see the incident note above for
# the measured hang durations this is sized against):
#   ATTEMPT_TIMEOUT_S=180 (3 minutes) is more than 10x smaller than the
#   SHORTEST observed real hang (40 minutes), so a genuine stall is
#   guaranteed to trip this timeout long before it could be mistaken for
#   "just slow" -- while still being generous headroom over a healthy
#   install of the package/dependency lists this repo's CI uses (normally
#   well under a minute on the GitHub-hosted runner's mirror).
#   MAX_ATTEMPTS=3 with BACKOFF_S=10 bounds the worst case for ONE call to
#   3 * 180s + 2 * 10s = 560s (~9.3 minutes) -- a small, fixed ceiling
#   instead of the unbounded hang this script replaces. A call site that
#   chains two calls (for example apt-get update then apt-get install)
#   has a worst case of roughly double that; see
#   .github/actions/apt-install-resilient/install.sh for that derivation.
ATTEMPT_TIMEOUT_S="${RETRY_ATTEMPT_TIMEOUT_S:-180}"
MAX_ATTEMPTS="${RETRY_MAX_ATTEMPTS:-3}"
BACKOFF_S="${RETRY_BACKOFF_S:-10}"

# This script also wraps the pip install in synthetic-coverage.yml's
# ubuntu+macos matrix, and the GitHub-hosted macOS runner image does not
# reliably ship GNU coreutils' `timeout` the way every Linux runner does.
# Prefer the real `timeout`/`gtimeout` binary when present (it also
# terminates a whole process GROUP, which a plain background+kill cannot);
# fall back to a bash watchdog otherwise so this script has no environment
# it silently degrades on. Resolved once, not per attempt, since a runner
# does not gain or lose coreutils mid-job.
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="gtimeout"
else
  TIMEOUT_BIN=""
fi

# run_bounded <seconds> <command...>: runs the command, returns its exit
# status, or 124 (matching GNU timeout's own convention, so the caller's
# "status -eq 124" check below works either way) if it is still running
# after <seconds>.
run_bounded() {
  local seconds="$1"
  shift
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "${seconds}s" "$@"
    return $?
  fi
  "$@" &
  local cmd_pid=$!
  (
    sleep "$seconds"
    kill -TERM "$cmd_pid" 2>/dev/null
  ) &
  local watchdog_pid=$!
  local cmd_status=0
  wait "$cmd_pid" 2>/dev/null || cmd_status=$?
  if kill -0 "$watchdog_pid" 2>/dev/null; then
    # The command finished on its own -- the watchdog is still sleeping.
    # Stop it so it cannot fire against a later, unrelated command.
    kill "$watchdog_pid" 2>/dev/null
    wait "$watchdog_pid" 2>/dev/null
    return "$cmd_status"
  fi
  # The watchdog already ran (it slept the full duration and sent
  # SIGTERM) -- report it the same way GNU timeout would.
  return 124
}

attempt=1
while true; do
  echo "retry-with-timeout: [$label] attempt ${attempt}/${MAX_ATTEMPTS} (timeout ${ATTEMPT_TIMEOUT_S}s): $*"
  run_bounded "${ATTEMPT_TIMEOUT_S}" "$@"
  status=$?

  if [ "${status}" -eq 0 ]; then
    echo "retry-with-timeout: [$label] succeeded on attempt ${attempt}"
    exit 0
  fi

  if [ "${status}" -eq 124 ]; then
    reason="timed out after ${ATTEMPT_TIMEOUT_S}s (looks like a stalled mirror/network -- the transient case this wrapper exists for)"
  else
    reason="exited ${status} (not a timeout; a real non-network failure reproduces this SAME code on every attempt, and retrying further will not fix it)"
  fi

  if [ "${attempt}" -ge "${MAX_ATTEMPTS}" ]; then
    echo "retry-with-timeout: [$label] failed all ${MAX_ATTEMPTS} attempts; last failure: ${reason}" >&2
    exit "${status}"
  fi

  echo "retry-with-timeout: [$label] attempt ${attempt} failed (${reason}); retrying in ${BACKOFF_S}s" >&2
  sleep "${BACKOFF_S}"
  attempt=$((attempt + 1))
done
