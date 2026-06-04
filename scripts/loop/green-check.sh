#!/usr/bin/env bash
#
# green-check.sh - the drill-loop "finish line".
#
# Returns exit 0 only when server/ is ready to hand off: type-check clean,
# full test suite passing, and lint clean. It adds NO new logic of its own;
# it only chains gates the repo already owns (server/package.json scripts).
#
# SCOPE (important, do not overclaim): these gates cover the server/ product
# code only. typecheck is `tsc --noEmit` (tsconfig include is src/**) and lint
# is `eslint src/`, so files OUTSIDE server/ (scripts/, etc.) are not type- or
# lint-checked here. A green result vouches for server/, not the whole tree.
# The test-baseline floor and transform-error detection remain owned by the
# pre-commit hook and .github/workflows/test-baseline-guard.yml; this script
# does not duplicate them.
#
# Used as the completion condition for the inner ("get to green") loop.
# See Review/Sanctuary/Drill_Loop_Recipe_2026-06-03.md for the full design.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$SCRIPT_DIR/../../server"

cd "$SERVER_DIR" || { echo "[green-check] FAIL: cannot cd to server dir ($SERVER_DIR)"; exit 2; }

echo "[green-check] 1/3 typecheck (vitest does not typecheck, so this runs explicitly)"
npm run typecheck || { echo "[green-check] FAIL: typecheck"; exit 1; }

echo "[green-check] 2/3 tests"
npm test || { echo "[green-check] FAIL: tests"; exit 1; }

echo "[green-check] 3/3 lint"
npm run lint || { echo "[green-check] FAIL: lint"; exit 1; }

echo "[green-check] PASS: server/ is green (typecheck + tests + lint)."
echo "[green-check] NOTE: gates cover server/ only; files outside server/ are not type/lint-checked here."
