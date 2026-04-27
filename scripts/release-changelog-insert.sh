#!/usr/bin/env bash
# release-changelog-insert.sh
#
# Reusable head/tail splice helper for inserting a CHANGELOG entry above an
# anchor regex. Idempotent: a no-op if the entry's header is already present.
#
# Future hotfix release scripts MUST call this helper rather than inlining
# their own awk insert. Multi-line awk -v variable expansion is silently
# unreliable on macOS BSD awk: the v1.1.3 release script used that pattern
# and dropped the entire CHANGELOG entry on a developer Mac (rescued by a
# follow-up backfill commit). The head + entry + tail splice this helper
# implements is BSD-portable and gives a verifiable post-write state.
#
# Usage:
#   release-changelog-insert.sh <changelog_path> <anchor_regex> <entry_file>
#
# Arguments:
#   changelog_path  Absolute or relative path to the CHANGELOG file.
#   anchor_regex    grep -E pattern that matches the line above which the
#                   new entry will be inserted. Conventionally something
#                   like "^## v1.1.2" — the first matching line wins.
#   entry_file      Path to a file containing the CHANGELOG entry to insert.
#                   The entry's first line should be the new version header
#                   (e.g. "## v1.1.4 - ...") so the idempotency check below
#                   can detect a re-run.
#
# Exit codes:
#   0  Splice succeeded, OR no-op because the entry header is already
#      present in the changelog.
#   1  Failure: missing file, anchor not found, post-write verification
#      failed, or argument problem.
#
# Idempotency:
#   The helper extracts the first "^## v" line from the entry file as the
#   "entry header" and skips the splice if grep finds that exact header in
#   the changelog. Re-runs are therefore safe.
#
# Why head + tail and not awk:
#   On BSD awk (macOS default) a `-v entry="$ENTRY"` substitution that
#   contains embedded newlines and double-quoted shell expansion can
#   silently lose content depending on the entry shape. The head + tail
#   splice has no such surface. See scripts/v1.1.3-changelog-backfill-2026-04-26.sh
#   in the v1.1.3 backfill for the original portable splice pattern.

set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "Usage: $0 <changelog_path> <anchor_regex> <entry_file>" >&2
  exit 1
fi

CHANGELOG="$1"
ANCHOR="$2"
ENTRY_FILE="$3"

if [[ ! -f "$CHANGELOG" ]]; then
  echo "FATAL: CHANGELOG file not found: $CHANGELOG" >&2
  exit 1
fi

if [[ ! -f "$ENTRY_FILE" ]]; then
  echo "FATAL: entry file not found: $ENTRY_FILE" >&2
  exit 1
fi

# Extract the new entry header (first "^## v" line) for idempotency.
ENTRY_HEADER=$(grep -m1 -E "^## v" "$ENTRY_FILE" || true)
if [[ -z "$ENTRY_HEADER" ]]; then
  echo "FATAL: entry file does not contain a '^## v' version header. Refusing to splice." >&2
  exit 1
fi

# Match the entry header as a literal-prefix line. If a header that starts
# with the same text is already present, skip the splice.
ENTRY_HEADER_PREFIX=$(printf '%s' "$ENTRY_HEADER" | awk '{print $1, $2}')
if grep -qF -- "$ENTRY_HEADER_PREFIX" "$CHANGELOG"; then
  echo "==> No-op: '$ENTRY_HEADER_PREFIX' already present in $CHANGELOG."
  exit 0
fi

# grep returns exit 1 on no match, which set -e + pipefail would treat as
# an abort. Suffix `|| true` so the empty-result check below produces the
# documented FATAL message instead of a silent exit.
INSERT_LINE=$(grep -nE "$ANCHOR" "$CHANGELOG" | head -1 | cut -d: -f1 || true)
if [[ -z "$INSERT_LINE" ]]; then
  echo "FATAL: anchor /$ANCHOR/ not found in $CHANGELOG." >&2
  exit 1
fi
echo "==> Anchor /$ANCHOR/ found at line $INSERT_LINE."

SPLICE_TMP=$(mktemp -t release-changelog-insert)
# shellcheck disable=SC2064
trap "rm -f '$SPLICE_TMP'" EXIT

head -n $((INSERT_LINE - 1)) "$CHANGELOG" > "$SPLICE_TMP"
cat "$ENTRY_FILE" >> "$SPLICE_TMP"
tail -n +"$INSERT_LINE" "$CHANGELOG" >> "$SPLICE_TMP"
mv "$SPLICE_TMP" "$CHANGELOG"

# Post-write verification.
if ! grep -qF -- "$ENTRY_HEADER_PREFIX" "$CHANGELOG"; then
  echo "FATAL: post-splice verification failed; '$ENTRY_HEADER_PREFIX' not found in $CHANGELOG after write." >&2
  exit 1
fi

echo "==> Splice verified. '$ENTRY_HEADER_PREFIX' inserted at line $INSERT_LINE of $CHANGELOG."
