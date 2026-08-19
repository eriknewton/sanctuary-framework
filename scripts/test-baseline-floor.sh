#!/usr/bin/env bash
#
# Sanctuary .test-baseline floor decision logic
# Copyright 2026 Erik Newton
# SPDX-License-Identifier: Apache-2.0
#
# Every decision the test-baseline floor mechanism makes lives here, as a
# subcommand with an exit code, so the whole mechanism is exercisable without a
# CI runner. The workflows call these subcommands and do the I/O a runner has to
# do (running the suite, reading and writing the cache); they contain no
# comparison of their own.
#
# THE SHAPE OF THE RULE (see AGENTS.md, "Commit discipline"):
#
#   On main, on push   after the suite runs, the observed passing count is
#                      PUBLISHED to an Actions cache entry scoped to the default
#                      branch. Nothing is committed, no branch is written, no
#                      pull request is opened, and the default token is the only
#                      credential involved.
#   On a pull request  the cached count is RESTORED and used as the floor. The
#                      observed count must not be BELOW it. A count above it is
#                      normal and passes.
#   When there is no   the committed integer in .test-baseline is used instead,
#   usable cache       loudly. That file stays in the tree as a slow-moving
#                      fallback floor that humans update rarely.
#
# THE HONEST BOUND, stated here because the docs must not overclaim it: a pull
# request fails when its count is below THE FLOOR IN FORCE. The floor in force is
# main's most recent completed CI count when a cache entry is available, and the
# committed fallback otherwise. While a floor is stale by D, a change can delete
# up to D passing tests and still pass. Publishing happens on every push to main,
# so D is normally zero once main's run completes, but it is not zero by
# construction and must never be described as if it were.
#
# Exit codes, uniform across subcommands:
#   0   the checked condition holds / proceed
#   1   the checked condition fails / refuse
#   2   usage error, or an input this script will not interpret (fail closed)
#
# A note on failing closed: every parse below refuses rather than guessing, with
# one deliberate exception. An unreadable CACHED floor falls back to the
# committed one rather than refusing, because a cache is allowed to be absent;
# that path is loud, and it can only ever raise the floor, never lower it.

set -euo pipefail

# The branch whose count is published and read back. Must match the `if:` on the
# publish step in .github/workflows/test-baseline-guard.yml.
readonly FLOOR_BRANCH_REF='refs/heads/main'

# The cache key prefix the publish step writes under and the restore step reads
# back with. Defined once here because a prefix that agrees on only one side is
# a floor that silently never loads: the restore misses, the fallback takes over,
# and everything stays green while asserting less. Must match the `key` and
# `restore-keys` in .github/workflows/test-baseline-guard.yml, which obtain it by
# calling `cache-key-prefix` rather than spelling it out.
readonly FLOOR_CACHE_KEY_PREFIX='baseline-floor-main-count-'

# The file inside the cached directory that carries the count. Same reasoning.
readonly FLOOR_CACHE_DIR='.baseline-floor-cache'
readonly FLOOR_CACHE_FILE="$FLOOR_CACHE_DIR/count"

usage() {
  cat >&2 <<'USAGE'
Usage: scripts/test-baseline-floor.sh <subcommand> [args]

  read-floor <floor-file>
      Print the committed fallback floor integer. Exit 2 if missing or
      malformed.

  parse-count <vitest-log>
      Print the passing-test count parsed from a captured vitest run.
      Exit 2 if the summary line is absent or not a plain integer.

  effective-floor <fallback> [cached]
      Print the floor in force on stdout and explain the choice on stderr.
      With a usable cached count, that is the HIGHER of the two, so a low
      cached value can never weaken the committed floor. With no usable
      cached count, it is the committed fallback, said out loud.

  assert-not-below <floor> <observed>
      The pull-request gate. Exit 0 when observed >= floor, 1 when below.

  publish-decision <ref> <measured-sha> <tip-sha>
      Exit 0 when this run may publish its count, 1 with a reason otherwise
      (not the default branch, or the branch moved while the suite ran).

  cache-key-prefix | cache-dir | cache-file
      Print the shared cache locations, so no workflow spells them out.

  drift-age-seconds <floor-file>
      Print how many seconds the tree has moved without the committed
      fallback being rewritten. Prints 0 when it is the newest change.

  fallback-drift-verdict <fallback> <observed> <age-seconds> <max-age-seconds> <max-gap>
      The scheduled backstop over the committed fallback. Exit 1 when the
      fallback sits above a fresh count, or when the gap below it is both
      large and old. Exit 0 otherwise: the fallback is slow-moving by design.
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
    echo "FAIL: $floor_file is missing. It must exist and hold a single integer, the committed fallback floor." >&2
    exit 2
  fi
  local raw
  raw="$(tr -d '[:space:]' < "$floor_file")"
  require_count "$floor_file" "$raw"
  printf '%s\n' "$raw"
}

# The single parser for vitest's passing count. The pull-request gate, the
# publisher, and the scheduled backstop all read the suite through this function,
# so the number the gate compares and the number that gets published cannot come
# from two regexes that drift. Real vitest summary line, ANSI stripped by
# NO_COLOR in the workflows:
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

# INVARIANT: the cached count may only ever RAISE the floor, never lower it.
# The cache is written by CI and is not reviewed by anyone, so treating a low
# cached value as authoritative would let an evicted, truncated, or simply stale
# entry silently weaken a floor that a human committed on purpose. Taking the
# higher of the two makes every cache failure mode fail towards the stricter
# number.
#
# The choice is always announced on stderr. A fallback that is preferred quietly
# is the failure this whole design is trying not to reintroduce: it looks
# identical to a healthy cached floor from the outside, and it asserts less.
#
# The number goes to stdout ALONE so a caller can capture it with `$(...)`;
# everything explanatory goes to stderr, where the runner prints it into the log.
cmd_effective_floor() {
  local fallback="${1:-}"
  local cached="${2-}"
  [[ -n "$fallback" ]] || die_usage "effective-floor needs <fallback> [cached]."
  require_count "committed fallback floor" "$fallback"

  if [[ -z "$cached" ]]; then
    echo "FALLBACK-IN-FORCE: no cached count from the default branch was available, so the floor is the committed fallback $fallback." >&2
    echo "  While the fallback is in force the floor is only as current as that file, and a change can delete up to the difference and still pass." >&2
    printf '%s\n' "$fallback"
    return 0
  fi

  if ! is_canonical_count "$cached"; then
    echo "FALLBACK-IN-FORCE: the cached count was present but unreadable ('$cached'), so the floor is the committed fallback $fallback." >&2
    echo "  An unreadable entry is more alarming than a missing one: something wrote a cache this gate cannot parse. Worth a look even though the gate is safe." >&2
    printf '%s\n' "$fallback"
    return 0
  fi

  if (( cached >= fallback )); then
    echo "CACHED-FLOOR-IN-FORCE: the default branch last counted $cached, at or above the committed fallback $fallback." >&2
    printf '%s\n' "$cached"
    return 0
  fi

  echo "COMMITTED-FLOOR-IN-FORCE: the cached count $cached is BELOW the committed fallback $fallback, so the committed value stands." >&2
  echo "  A cached value never lowers the floor. If the default branch genuinely counts fewer tests now, lower the committed fallback deliberately, with a written justification." >&2
  printf '%s\n' "$fallback"
}

# INVARIANT: this asserts a FLOOR and nothing else. It does not demand equality
# and it does not ask the author to record anything, because the number it
# compares against is published by CI on the default branch. Demanding equality
# here is what forced every pull request to guess an integer computed on a
# platform the author cannot run.
cmd_assert_not_below() {
  local floor="${1:-}"
  local observed="${2:-}"
  [[ -n "$floor" && -n "$observed" ]] || die_usage "assert-not-below needs <floor> <observed>."
  require_count "floor" "$floor"
  require_count "observed count" "$observed"

  if (( observed < floor )); then
    echo "FAIL: test baseline regression. Floor in force: $floor. Observed passing: $observed. Missing $((floor - observed)) tests." >&2
    echo "  Restore the tests, or lower the floor deliberately with a written justification (see AGENTS.md)." >&2
    exit 1
  fi
  if (( observed > floor )); then
    echo "OK: $observed passing, $((observed - floor)) above the floor in force of $floor."
    exit 0
  fi
  echo "OK: $observed passing, exactly at the floor in force."
}

# INVARIANT: a run publishes only the count that describes the CURRENT tip of the
# default branch. Two pushes in quick succession can finish out of order, and a
# slower older run must not overwrite a newer count with an older one; the
# restore side picks the most recently created entry, so ordering is decided
# here, not there. A run whose commit is no longer the tip simply declines: the
# newer push has its own run and publishes from it.
cmd_publish_decision() {
  local ref="${1:-}"
  local measured_sha="${2:-}"
  local tip_sha="${3:-}"
  [[ -n "$ref" && -n "$measured_sha" && -n "$tip_sha" ]] \
    || die_usage "publish-decision needs <ref> <measured-sha> <tip-sha>."

  if [[ "$ref" != "$FLOOR_BRANCH_REF" ]]; then
    echo "DECLINE: a count is published from $FLOOR_BRANCH_REF only, and this ran on '$ref'." >&2
    exit 1
  fi
  if [[ "$measured_sha" != "$tip_sha" ]]; then
    echo "DECLINE: the suite measured $measured_sha but the branch is now at $tip_sha; the newer push publishes its own count." >&2
    exit 1
  fi
  echo "OK: publishing the observed count for $measured_sha."
}

cmd_cache_key_prefix() { printf '%s\n' "$FLOOR_CACHE_KEY_PREFIX"; }
cmd_cache_dir()        { printf '%s\n' "$FLOOR_CACHE_DIR"; }
cmd_cache_file()       { printf '%s\n' "$FLOOR_CACHE_FILE"; }

# How long the tree has moved on without the committed fallback being rewritten.
# Measured from the FIRST commit that followed its last change, not from the
# newest commit, because a busy branch keeps the newest commit young forever and
# would keep a permanently stale fallback inside any grace window.
#
# Failure mode note for whoever reads this at 2am: a shallow clone has no such
# history and this returns 0, which reads as "no drift", so the workflow that
# calls it checks out with full history. A truncated history looks exactly like
# a fresh fallback from here.
cmd_drift_age_seconds() {
  local floor_file="${1:-}"
  [[ -n "$floor_file" ]] || die_usage "drift-age-seconds needs a floor file path."

  local floor_commit=""
  floor_commit="$(git log -1 --format=%H -- "$floor_file" 2>/dev/null || true)"
  if [[ -z "$floor_commit" ]]; then
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

# INVARIANT: the committed fallback is SUPPOSED to lag. It is the floor of last
# resort, not a live number, so an ordinary gap is not news and alarming on every
# gap would train everyone to ignore this check. Two things are news:
#
#   - the fallback sitting ABOVE a fresh count, which blocks every pull request
#     with a regression that is not one, and
#   - a gap that is both large and old, which means the fallback has decayed far
#     enough that it would protect almost nothing if the cache went away.
cmd_fallback_drift_verdict() {
  local fallback="${1:-}"
  local observed="${2:-}"
  local age="${3:-}"
  local max_age="${4:-}"
  local max_gap="${5:-}"
  [[ -n "$fallback" && -n "$observed" && -n "$age" && -n "$max_age" && -n "$max_gap" ]] \
    || die_usage "fallback-drift-verdict needs <fallback> <observed> <age-seconds> <max-age-seconds> <max-gap>."
  require_count "committed fallback floor" "$fallback"
  require_count "observed count" "$observed"
  require_count "fallback age in seconds" "$age"
  require_count "maximum age in seconds" "$max_age"
  require_count "maximum gap" "$max_gap"

  if (( observed < fallback )); then
    echo "FAIL: the committed fallback floor $fallback is ABOVE a fresh count of $observed on the default branch." >&2
    echo "  Every pull request that falls back to it will red with a regression that is not one. Lower it deliberately, with a written justification." >&2
    exit 1
  fi

  if (( observed == fallback )); then
    echo "IN-SYNC: the committed fallback and a fresh count both read $fallback."
    return 0
  fi

  local gap=$(( observed - fallback ))
  if (( gap <= max_gap )) || (( age < max_age )); then
    echo "FALLBACK-LAGGING-ACCEPTABLY: fallback $fallback, fresh count $observed, gap $gap (max $max_gap), age ${age}s (max ${max_age}s). The fallback is slow-moving by design."
    return 0
  fi

  echo "FAIL: the committed fallback floor has decayed. Fallback: $fallback. Fresh count: $observed. Gap: $gap, past the $max_gap tolerated, and ${age}s old, past ${max_age}s." >&2
  echo "  If the cached floor ever became unavailable, this is the number every pull request would be held to, and it would let $gap deletions through." >&2
  echo "  Raise the committed fallback in a scoped commit." >&2
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
    read-floor)             cmd_read_floor "$@" ;;
    parse-count)            cmd_parse_count "$@" ;;
    effective-floor)        cmd_effective_floor "$@" ;;
    assert-not-below)       cmd_assert_not_below "$@" ;;
    publish-decision)       cmd_publish_decision "$@" ;;
    cache-key-prefix)       cmd_cache_key_prefix "$@" ;;
    cache-dir)              cmd_cache_dir "$@" ;;
    cache-file)             cmd_cache_file "$@" ;;
    drift-age-seconds)      cmd_drift_age_seconds "$@" ;;
    fallback-drift-verdict) cmd_fallback_drift_verdict "$@" ;;
    -h|--help|help)         usage; exit 0 ;;
    *)                      die_usage "Unknown subcommand: $subcommand" ;;
  esac
}

main "$@"
