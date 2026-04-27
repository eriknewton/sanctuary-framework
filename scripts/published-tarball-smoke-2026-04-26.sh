#!/usr/bin/env bash
# Sanctuary v1.1.2 Pre-Promote Smoke (Finding V verification)
#
# Operators following the v1.1.1 release notes hit 404 on the v1.1
# dashboard at the wrap-emitted URL because PR #82's wiring landed only
# on the principal-policy dashboard server, not the wrap-auto dashboard
# server. This script proves that BUG IS GONE in the to-be-published
# tarball before the dist-tag flips to `latest`.
#
# Usage (from a developer Mac with the v1.1.2 tag built):
#
#   bash scripts/published-tarball-smoke-2026-04-26.sh
#
# What it does:
#
#   1. Runs `npm pack` against the v1.1.2 server tree to build the actual
#      to-be-published tarball (NOT a fetch from the registry).
#   2. Installs it into a clean tmp dir (no pollution of the developer's
#      global node_modules or ~/.sanctuary).
#   3. Runs `sanctuary wrap --claude-code --fortress <tmp>` against an
#      isolated HOME so ~/.claude.json on the developer Mac is untouched.
#   4. Captures the printed dashboard URL + token from wrap stdout.
#   5. Curls the three v1.1 endpoints (/v1.1, /api/hub/agents,
#      /api/identities) and asserts each returns 200.
#   6. Asserts the persisted ~/.claude.json (in tmp HOME) carries
#      SANCTUARY_FORTRESS_PATH = the absolute --fortress path (Finding W).
#   7. Tears down the wrap subprocess + tmp HOME + tmp fortress.
#
# Exit code: 0 on all checks pass; non-zero on any failure (do NOT
# promote `latest` if non-zero).
#
# Requirements: bash, curl, jq, node 18+. Run on macOS or Linux.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_DIR="${REPO_ROOT}/server"
SMOKE_HOME=""
WRAP_PID=""

cleanup() {
  if [[ -n "${WRAP_PID}" ]] && kill -0 "${WRAP_PID}" 2>/dev/null; then
    kill "${WRAP_PID}" 2>/dev/null || true
    wait "${WRAP_PID}" 2>/dev/null || true
  fi
  if [[ -n "${SMOKE_HOME}" ]] && [[ -d "${SMOKE_HOME}" ]]; then
    rm -rf "${SMOKE_HOME}"
  fi
}
trap cleanup EXIT

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERROR: $1 not found on PATH (required by this smoke script)" >&2
    exit 2
  }
}
require curl
require jq
require node
require npm

echo "==> Building tarball from ${SERVER_DIR}"
cd "${SERVER_DIR}"
TARBALL=$(npm pack --silent | tail -1)
TARBALL_ABS="${SERVER_DIR}/${TARBALL}"
[[ -f "${TARBALL_ABS}" ]] || {
  echo "ERROR: tarball not produced at ${TARBALL_ABS}" >&2
  exit 2
}
echo "    Built: ${TARBALL}"

echo "==> Setting up isolated install directory"
SMOKE_HOME=$(mktemp -d -t v1_1_2_smoke_XXXXXXXX)
INSTALL_DIR="${SMOKE_HOME}/install"
TMP_FORTRESS="${SMOKE_HOME}/fortress"
mkdir -p "${INSTALL_DIR}" "${TMP_FORTRESS}"

echo "==> Installing tarball into ${INSTALL_DIR}"
cd "${INSTALL_DIR}"
npm init -y >/dev/null
npm install --no-audit --no-fund --silent "${TARBALL_ABS}"

SANCTUARY_BIN="${INSTALL_DIR}/node_modules/.bin/sanctuary"
[[ -x "${SANCTUARY_BIN}" ]] || {
  echo "ERROR: sanctuary binary not found at ${SANCTUARY_BIN}" >&2
  exit 2
}

echo "==> Running sanctuary wrap with isolated HOME and tmp fortress"
WRAP_LOG="${SMOKE_HOME}/wrap.log"
HOME="${SMOKE_HOME}" \
SANCTUARY_PASSPHRASE="smoke-test-passphrase-do-not-use-in-prod" \
SANCTUARY_DASHBOARD_AUTH_TOKEN="smoke-token-fixed-for-deterministic-curl" \
"${SANCTUARY_BIN}" wrap --claude-code --fortress "${TMP_FORTRESS}" --no-open \
  > "${WRAP_LOG}" 2>&1 &
WRAP_PID=$!

# Give wrap up to 30s to print the URL + bind the dashboard.
URL=""
for i in $(seq 1 30); do
  if grep -q "Sovereignty Dashboard running" "${WRAP_LOG}" 2>/dev/null; then
    URL=$(grep -o 'http://127.0.0.1:[0-9]*' "${WRAP_LOG}" | head -1)
    break
  fi
  sleep 1
done

[[ -n "${URL}" ]] || {
  echo "ERROR: wrap did not print a dashboard URL within 30s. wrap.log:" >&2
  cat "${WRAP_LOG}" >&2
  exit 2
}
echo "    Dashboard URL: ${URL}"

echo "==> Probing v1.1 surfaces"
fail=0

probe() {
  local path="$1"
  local label="$2"
  local code
  code=$(curl -sS -o /dev/null -w "%{http_code}" "${URL}${path}")
  if [[ "${code}" == "200" ]]; then
    echo "    PASS: ${label} (${path}) → 200"
  else
    echo "    FAIL: ${label} (${path}) → ${code} (expected 200)" >&2
    fail=1
  fi
}

probe "/v1.1"             "v1.1 dashboard HTML"
probe "/api/hub/agents"   "v1.1 hub agents API"
probe "/api/identities"   "Finding E /api/identities alias"
probe "/"                 "legacy v1.0 dashboard"

echo "==> Asserting ~/.claude.json persisted SANCTUARY_FORTRESS_PATH (Finding W)"
CLAUDE_JSON="${SMOKE_HOME}/.claude.json"
if [[ ! -f "${CLAUDE_JSON}" ]]; then
  echo "    FAIL: ${CLAUDE_JSON} not written by wrap" >&2
  fail=1
else
  PERSISTED=$(jq -r '.mcpServers.sanctuary.env.SANCTUARY_FORTRESS_PATH // empty' "${CLAUDE_JSON}")
  EXPECTED="${TMP_FORTRESS}"
  # Resolve expected to absolute the same way Commit 3 does.
  EXPECTED_ABS=$(cd "${EXPECTED}" 2>/dev/null && pwd || echo "${EXPECTED}")
  if [[ "${PERSISTED}" == "${EXPECTED_ABS}" ]]; then
    echo "    PASS: SANCTUARY_FORTRESS_PATH = ${PERSISTED}"
  else
    echo "    FAIL: SANCTUARY_FORTRESS_PATH mismatch" >&2
    echo "         expected: ${EXPECTED_ABS}" >&2
    echo "         got:      ${PERSISTED:-<unset>}" >&2
    fail=1
  fi
fi

echo
if [[ "${fail}" == "0" ]]; then
  echo "==> v1.1.2 pre-promote smoke: PASS. Safe to flip dist-tag to latest."
  exit 0
else
  echo "==> v1.1.2 pre-promote smoke: FAIL. Do NOT promote latest." >&2
  echo "    wrap.log preserved at ${WRAP_LOG} for triage." >&2
  # Suppress trap cleanup so the operator can inspect.
  trap - EXIT
  if [[ -n "${WRAP_PID}" ]] && kill -0 "${WRAP_PID}" 2>/dev/null; then
    kill "${WRAP_PID}" 2>/dev/null || true
  fi
  echo "    SMOKE_HOME (preserved for triage): ${SMOKE_HOME}" >&2
  exit 1
fi
