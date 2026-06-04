#!/usr/bin/env bash
#
# green-check.sh - the drill-loop "finish line".
#
# Returns exit 0 only when server/ is ready to hand off: type-check clean and
# the full test suite passing (plus lint, when the repo actually owns a lint
# gate). It adds NO new logic of its own; it only chains gates the repo already
# owns (server/package.json scripts).
#
# SCOPE (important, do not overclaim): these gates cover the server/ product
# code only. typecheck is `tsc --noEmit` (tsconfig include is src/**), so files
# OUTSIDE server/ (scripts/, etc.) are not type-checked here. A green result
# vouches for server/, not the whole tree. The test-baseline floor and
# transform-error detection remain owned by the pre-commit hook and
# .github/workflows/test-baseline-guard.yml; this script does not duplicate them.
#
# LINT: the `lint` script is `eslint src/`, but eslint is not currently a
# dependency and the repo ships no eslint config, so `npm run lint` exits 127
# (command not found) on a clean install -- there is no working lint gate to
# chain today. This script therefore runs lint ONLY when an eslint binary is
# actually present, and otherwise loudly SKIPs it rather than hard-failing or
# silently claiming lint passed. Wire eslint up (dep + config) and the step
# auto-activates. Owned, working gates today: typecheck + tests.
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
# Only gate on lint when an eslint binary is actually resolvable (server-local,
# repo-root, or PATH) -- mirrors npm's node_modules/.bin resolution. If absent,
# the repo owns no working lint gate; SKIP loudly instead of overclaiming.
if [ -x node_modules/.bin/eslint ] || [ -x ../node_modules/.bin/eslint ] || command -v eslint >/dev/null 2>&1; then
  LINT_RAN=1
  npm run lint || { echo "[green-check] FAIL: lint"; exit 1; }
else
  LINT_RAN=0
  echo "[green-check] SKIP: lint -- no eslint binary or eslint config in this repo."
  echo "[green-check]       typecheck + tests are the gates the repo actually owns;"
  echo "[green-check]       wire eslint up (dep + config) to auto-activate this step."
fi

if [ "$LINT_RAN" -eq 1 ]; then
  echo "[green-check] PASS: server/ is green (typecheck + tests + lint)."
else
  echo "[green-check] PASS: server/ is green (typecheck + tests; lint skipped -- not owned)."
fi
echo "[green-check] NOTE: gates cover server/ only; files outside server/ are not type-checked here."
