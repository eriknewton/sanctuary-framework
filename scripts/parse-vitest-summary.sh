#!/usr/bin/env bash
#
# Parse the Vitest passing-test count for the baseline guard.
# Copyright 2026 Erik Newton
# SPDX-License-Identifier: Apache-2.0
#
# Shared by .githooks/pre-push and .github/workflows/test-baseline-guard.yml.
# The caller-side comments in both files must match this contract.

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
summary_lines=$(printf '%s\n' "$stripped_output" | grep -E "$SUMMARY_LINE_RE" || true)
if [[ -z "$summary_lines" ]]; then
  emit_error "Could not parse passing-test count from vitest output."
  emit_error "Expected one vitest summary line matching 'Tests <N> passed' after ANSI stripping; none was found."
  exit 1
fi

summary_line_count=$(printf '%s\n' "$summary_lines" | wc -l | tr -d '[:space:]')
if [[ "$summary_line_count" != "1" ]]; then
  emit_error "Could not parse passing-test count from vitest output."
  emit_error "Found $summary_line_count lines shaped like the vitest 'Tests <N> passed' summary; expected exactly one."
  emit_error "Test output that prints its own summary-shaped line makes the count ambiguous, so the baseline guard refuses to pick one:"
  printf '%s\n' "$summary_lines" >&2
  exit 1
fi

passing=$(printf '%s\n' "$summary_lines" | sed -E 's/^[[:space:]]*Tests[[:space:]]+([0-9]+) passed.*/\1/')
if [[ -z "$passing" ]]; then
  emit_error "Could not parse passing-test count from vitest output."
  emit_error "The summary line was found but no count could be read from it: $summary_lines"
  exit 1
fi

printf '%s\n' "$passing"
