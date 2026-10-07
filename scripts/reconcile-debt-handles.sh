#!/usr/bin/env bash
# reconcile-debt-handles.sh — coordinator-side DEBT-handle-to-register reconciler.
#
# THE OTHER HALF of AGENTS.md rule 9's mechanical reconciliation. The public
# half lives in this repo as a structural test
# (server/test/structure/debt-handle-register-reconciliation.test.ts): it
# asserts every `DEBT(<HANDLE>)` marker across server/src, server/test,
# castle-wall-daemon/src, and castle-wall-daemon/tests is uniquely shaped, but
# it can never read the private `Open_Defects_Register` (that lives in the
# coordinator repo, across a repository boundary a public CI job cannot
# cross). This script is the piece that DOES read the register, run by a
# coordinator who has both repos checked out. It never runs in this
# repository's CI.
#
# WHAT THIS SCRIPT DOES: scans for every `DEBT(<HANDLE>)` marker (file, line,
# handle) and prints them. Given a register path, it ALSO reports which
# handles have no matching row in that file, so a coordinator can see at a
# glance what still needs a register entry.
#
# WHAT THIS SCRIPT NEVER DOES: it never writes to the register, never writes
# to the source tree, and never prints defect prose. A handle with no register
# row is a to-do (an id), not a description of anything -- keep it that way.
#
# Usage:
#   scripts/reconcile-debt-handles.sh                     # list handles only
#   scripts/reconcile-debt-handles.sh <register-path>      # + unmatched report
#
# <register-path> is expected to be a private register file, e.g.
#   ~/Code/Claude/Review/Sanctuary/Open_Defects_Register_2026-08-05.md
# A handle counts as matched when it appears in the register file as a WHOLE
# TOKEN -- not preceded or followed by another handle-shape character
# ([A-Z0-9-]) -- so "BRIDGE-SELF-INFLATION" does not false-match a register
# row that only contains "BRIDGE-SELF-INFLATION-2" or
# "PRE-BRIDGE-SELF-INFLATION". This is still a coarse reconciliation aid for a
# human to review, not an authoritative cross-reference.
#
# EXIT CODES (a coordinator or a wrapping script can branch on these):
#   0 -- a register path was given, it was read, and every handle found has a
#        matching register row. A bare listing never exits 0: see 2.
#   1 -- the register was read but at least one handle has no matching row.
#   2 -- a register path was given but does not exist / is not a readable
#        file, OR no register path was given at all. A bare listing (no
#        argument) is a usage shortfall for reconciliation purposes, not a
#        passing reconciliation, so it does not read as success.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REGISTER_PATH="${1:-}"

# Mirrors the structural test's SCAN_ROOTS exactly (server/test/structure/
# debt-handle-register-reconciliation.test.ts) -- same four roots, same
# exclusion of __fixtures__, same never-scan-markdown rule. Keep the two in
# sync: a root added to one belongs in the other.
SCAN_DIRS=()
for candidate in "server/src" "server/test" "castle-wall-daemon/src" "castle-wall-daemon/tests"; do
  if [[ -d "$candidate" ]]; then
    SCAN_DIRS+=("$candidate")
  fi
done

# Same shape rule as the structural test: DEBT(<HANDLE>) where <HANDLE>
# matches ^[A-Z][A-Z0-9-]{2,40}$. This script is READ-ONLY: a marker that does
# not match this shape is simply not counted as a handle (the structural test
# is what enforces the shape; this script's job is reconciliation, not
# linting).
HANDLE_REGEX='DEBT\(([A-Z][A-Z0-9-]{2,40})\)'

HANDLES_FILE="$(mktemp)"
RAW_FILE="$(mktemp)"
FILTERED_FILE="${RAW_FILE}.filtered"
# All three temp files are named here so a script failure between their
# creation and the final `mv` below (which replaces RAW_FILE with
# FILTERED_FILE, but does not always leave a file at the FILTERED_FILE path
# to clean up) still cleans up whichever of the two happens to exist on exit.
trap 'rm -f "$HANDLES_FILE" "$RAW_FILE" "$FILTERED_FILE"' EXIT

: > "$RAW_FILE"
for dir in "${SCAN_DIRS[@]}"; do
  # grep -r over the whole dir in one call, rather than per-file, so a
  # directory with zero matches (grep exit 1) can never abort this script
  # under `set -e -o pipefail` the way a per-file loop would.
  grep -rnoE --include='*.ts' --include='*.rs' "$HANDLE_REGEX" "$dir" >> "$RAW_FILE" || true
done

# Drop anything under a __fixtures__ directory (grep's recursive match
# already gives us "path:line:match"; filter on the path segment). "test"
# itself is NOT filtered here: server/test and castle-wall-daemon/tests are
# scan roots, same as the structural test.
grep -vE '/__fixtures__/' "$RAW_FILE" > "$FILTERED_FILE" || true
mv "$FILTERED_FILE" "$RAW_FILE"

while IFS=: read -r file line_no match; do
  handle="${match#DEBT(}"
  handle="${handle%)}"
  printf '%s\t%s\t%s\n' "$handle" "$file" "$line_no"
done < "$RAW_FILE" | sort -t"$(printf '\t')" -k1,1 -k2,2 -k3,3n > "$HANDLES_FILE"

if [[ ! -s "$HANDLES_FILE" ]]; then
  echo "No DEBT(<HANDLE>) markers found under: ${SCAN_DIRS[*]}"
  if [[ -z "$REGISTER_PATH" ]]; then
    exit 2
  fi
  exit 0
fi

echo "DEBT handles found (handle, file, line):"
while IFS=$'\t' read -r handle file line_no; do
  printf '  %-45s %s:%s\n' "$handle" "$file" "$line_no"
done < "$HANDLES_FILE"

DISTINCT_HANDLES="$(cut -f1 "$HANDLES_FILE" | sort -u)"
DISTINCT_COUNT="$(printf '%s\n' "$DISTINCT_HANDLES" | grep -c . || true)"
echo ""
echo "Distinct handles: $DISTINCT_COUNT"

if [[ -z "$REGISTER_PATH" ]]; then
  echo ""
  echo "No register path given -- pass one to reconcile against it, e.g.:"
  echo "  $0 ~/Code/Claude/Review/Sanctuary/Open_Defects_Register_2026-08-05.md"
  echo "A bare listing does not reconcile anything, so this is not success."
  exit 2
fi

if [[ ! -f "$REGISTER_PATH" ]]; then
  echo ""
  echo "FAIL: register path does not exist or is not a file: $REGISTER_PATH" >&2
  exit 2
fi

echo ""
echo "Reconciling against register: $REGISTER_PATH"

UNMATCHED=()
while IFS= read -r handle; do
  [[ -z "$handle" ]] && continue
  # Whole-token match: the handle must not be immediately preceded or
  # followed by another handle-shape character. grep -E has no \b that
  # respects "-" as a boundary (word-boundary treats "-" as non-word on both
  # sides, which is exactly wrong for a handle like "BRIDGE-SELF-INFLATION"
  # sitting inside a longer hyphenated token), so the boundary is spelled out
  # explicitly on both sides instead.
  if ! grep -qE "(^|[^A-Z0-9-])${handle}([^A-Z0-9-]|\$)" "$REGISTER_PATH"; then
    UNMATCHED+=("$handle")
  fi
done <<< "$DISTINCT_HANDLES"

if [[ "${#UNMATCHED[@]}" -eq 0 ]]; then
  echo "All $DISTINCT_COUNT handle(s) have a matching row in the register."
  exit 0
fi

echo "Handle(s) with NO matching row in the register (${#UNMATCHED[@]}):"
for handle in "${UNMATCHED[@]}"; do
  echo "  $handle"
done
exit 1
