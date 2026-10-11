#!/usr/bin/env bash
#
# Parse the Vitest passing-test count for the baseline guard.
# Copyright 2026 Erik Newton
# SPDX-License-Identifier: Apache-2.0
#
# Shared by .githooks/pre-push and .github/workflows/test-baseline-guard.yml.
# The caller-side comments in both files must match this contract.
#
# Two ways to use it:
#   - Run it with a log path: prints the one passing-test count (a canonical
#     non-negative integer of any length) or refuses with a named error on zero
#     summary lines, several summary lines, several counts on one line, or a
#     non-canonical count.
#   - Source it: defines emit_error, strip_ansi, is_canonical_count,
#     compare_counts, count_difference and read_canonical_floor, and returns
#     before parsing. The
#     pre-push hook compares counts only through compare_counts, so it has no
#     digit ceiling and does no overflow-prone arithmetic on a count.

set -euo pipefail

emit_error() {
  local message="$1"
  if [[ "${VITEST_SUMMARY_ERROR_STYLE:-}" == "github" || "${GITHUB_ACTIONS:-}" == "true" ]]; then
    printf '::error::%s\n' "$message" >&2
  else
    printf '%s%s\n' "${VITEST_SUMMARY_ERROR_PREFIX:-}" "$message" >&2
  fi
}

strip_ansi() {
  LC_ALL=C sed $'s/\033\\[[0-?]*[ -/]*[@-~]//g'
}

# A count is a canonical non-negative integer: digits only, no sign, no
# leading zero (so a bare "0" is the only count that starts with 0). Any digit
# count is accepted; there is deliberately no upper ceiling here, because the
# comparison below never does arithmetic on a whole count.
# Must match CANONICAL_COUNT_RE callers: is_canonical_count and compare_counts
# below, and the floor checks in .githooks/pre-push.
CANONICAL_COUNT_RE='^(0|[1-9][0-9]*)$'

is_canonical_count() {
  [[ "${1-}" =~ $CANONICAL_COUNT_RE ]]
}

# compare_counts <a> <b>: print "lt", "eq" or "gt" for a versus b.
# INVARIANT: counts are compared as digit strings (shorter is smaller, then the
# first differing digit decides), never with (( )), because bash arithmetic is
# signed 64-bit and wraps silently: a count of 2^64 + baseline would compare
# equal to the baseline. Comparing strings has no overflow, so no digit ceiling
# is needed for correctness at any length.
# FAILURE MODE: a non-canonical operand (empty, signed, leading zero, any
# non-digit) is refused with a named error and status 1, never compared; a
# caller must test the status (`if ! rel=$(compare_counts ...)`), since a
# refusal prints nothing on stdout.
compare_counts() {
  local a="${1-}" b="${2-}" i da db
  if ! is_canonical_count "$a" || ! is_canonical_count "$b"; then
    emit_error "Cannot compare counts '$a' and '$b': each must be a canonical non-negative integer (digits only, no sign, no leading zero)."
    return 1
  fi
  if (( ${#a} != ${#b} )); then
    if (( ${#a} < ${#b} )); then printf 'lt\n'; else printf 'gt\n'; fi
    return 0
  fi
  for (( i = 0; i < ${#a}; i++ )); do
    da="${a:i:1}"
    db="${b:i:1}"
    if [[ "$da" != "$db" ]]; then
      # Single decimal digits: (( )) on one digit cannot overflow.
      if (( da < db )); then printf 'lt\n'; else printf 'gt\n'; fi
      return 0
    fi
  done
  printf 'eq\n'
}

# read_canonical_floor: read the raw bytes of a .test-baseline file on stdin
# and print the floor. The content must be exactly one canonical count,
# optionally followed by ONE newline; nothing else.
# INVARIANT: the raw bytes are validated as they are, never after stripping
# whitespace: stripping first would turn "123 4567" or "123\n4567" into a valid
# 7-digit floor nobody wrote. The bytes are checked as hex pairs from od, which
# keeps NUL and CR bytes visible (a bash variable silently drops NUL).
# Must match every .test-baseline read: the Rule (a) and Rule (b) floor reads in
# .githooks/pre-push.
# FAILURE MODE: anything else (empty, a space, an inner or second newline,
# CRLF, a sign, a leading zero, any other byte) is refused with a named error
# and status 1, printing nothing on stdout; a caller must test the status.
# Hex patterns: 30-39 are the ASCII digits 0-9 and 0a is a line feed.
FLOOR_HEX_RE='^(30|3[1-9](3[0-9])*)(0a)?$'
read_canonical_floor() {
  local hex count i
  if ! hex=$(LC_ALL=C od -An -v -tx1 | tr -d ' \n'); then
    emit_error "Could not read the .test-baseline bytes."
    return 1
  fi
  if ! [[ "$hex" =~ $FLOOR_HEX_RE ]]; then
    emit_error ".test-baseline must be exactly one canonical non-negative integer (digits only, no leading zero) with at most one trailing newline; spaces, inner newlines, CRLF and any other byte are refused."
    return 1
  fi
  hex="${hex%0a}"
  count=""
  # Each pair is "3d" for digit d, so the digit is the pair's second character.
  for (( i = 1; i < ${#hex}; i += 2 )); do
    count="${count}${hex:i:1}"
  done
  printf '%s\n' "$count"
}

# 18 = one fewer than the 19 digits of 9223372036854775807 (2^63 - 1, bash's
# largest arithmetic value), so every count of at most 18 digits fits.
ARITH_SAFE_DIGITS=18

# count_difference <larger> <smaller>: print larger - smaller for a message.
# Display only: decisions use compare_counts. When either count is too long
# for exact bash arithmetic it says so instead of printing a wrapped number.
count_difference() {
  local larger="${1-}" smaller="${2-}"
  if ! is_canonical_count "$larger" || ! is_canonical_count "$smaller"; then
    printf '(not computable)\n'
  elif (( ${#larger} > ARITH_SAFE_DIGITS || ${#smaller} > ARITH_SAFE_DIGITS )); then
    printf '(too long to subtract exactly)\n'
  else
    printf '%s\n' "$(( 10#$larger - 10#$smaller ))"
  fi
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

if [[ "$#" != "1" ]]; then
  emit_error "Usage: scripts/parse-vitest-summary.sh <vitest-output-log>"
  exit 1
fi

log_path="$1"
if [[ ! -f "$log_path" ]]; then
  emit_error "Vitest output log not found: $log_path"
  exit 1
fi

if ! stripped_output=$(strip_ansi < "$log_path"); then
  emit_error "Could not strip ANSI escape sequences from the vitest output."
  exit 1
fi

# INVARIANT: test stdout is not trusted, so the count is accepted only when
# exactly one Vitest summary-shaped line remains after ANSI stripping. Picking
# the first or last matching line would make the baseline count ambiguous.
SUMMARY_LINE_RE='^[[:space:]]*Tests[[:space:]]+[0-9]+ passed'
SUMMARY_COUNT_RE='Tests[[:space:]]+[0-9]+ passed'
EXPECTED_SUMMARY_COUNT=1
summary_lines=$(printf '%s\n' "$stripped_output" | grep -E "$SUMMARY_LINE_RE" || true)
if [[ -z "$summary_lines" ]]; then
  emit_error "Could not parse passing-test count from vitest output."
  emit_error "Expected one vitest summary line matching 'Tests <N> passed' after ANSI stripping; none was found."
  exit 1
fi

summary_line_count=$(printf '%s\n' "$summary_lines" | wc -l | tr -d '[:space:]')
if [[ "$summary_line_count" != "$EXPECTED_SUMMARY_COUNT" ]]; then
  emit_error "Could not parse passing-test count from vitest output."
  emit_error "Found $summary_line_count lines shaped like the vitest 'Tests <N> passed' summary; expected exactly one."
  emit_error "Test output that prints its own summary-shaped line makes the count ambiguous, so the baseline guard refuses to pick one:"
  printf '%s\n' "$summary_lines" >&2
  exit 1
fi

summary_count_matches=$(printf '%s\n' "$summary_lines" | grep -oE "$SUMMARY_COUNT_RE" | wc -l | tr -d '[:space:]')
if [[ "$summary_count_matches" != "$EXPECTED_SUMMARY_COUNT" ]]; then
  emit_error "Could not parse passing-test count from vitest output."
  emit_error "Found $summary_count_matches count-shaped matches inside the vitest summary line; expected exactly one."
  emit_error "A single line with more than one 'Tests <N> passed' count is ambiguous, so the baseline guard refuses to pick one:"
  printf '%s\n' "$summary_lines" >&2
  exit 1
fi

passing=$(printf '%s\n' "$summary_lines" | grep -oE "$SUMMARY_COUNT_RE" | sed -E 's/^Tests[[:space:]]+([0-9]+) passed$/\1/')
if [[ -z "$passing" ]]; then
  emit_error "Could not parse passing-test count from vitest output."
  emit_error "The summary line was found but no count could be read from it: $summary_lines"
  exit 1
fi

# INVARIANT: the parser's output is always a canonical count, so a consumer
# never has to re-validate its shape before comparing; a leading-zero count is
# refused here rather than handed on (bash arithmetic would read it as octal).
if ! is_canonical_count "$passing"; then
  emit_error "Could not parse passing-test count from vitest output."
  emit_error "The summary count '$passing' is not a canonical non-negative integer (digits only, no leading zero)."
  exit 1
fi

printf '%s\n' "$passing"
