#!/usr/bin/env bash
# Sanctuary v1.1.3 Pre-Promote Smoke (Findings V + W + X verification)
#
# Operators following the v1.1.1 release notes hit 404 on the v1.1
# dashboard at the wrap-emitted URL because PR #82's wiring landed only
# on the principal-policy dashboard server, not the wrap-auto dashboard
# server. v1.1.2 closed that. v1.1.3 closes Finding X: a fresh wrap
# without an env-supplied passphrase generated one and never disclosed
# it, leaving the operator without an off-host backup.
#
# This script proves both bug classes are GONE in the to-be-published
# tarball before the dist-tag flips to `latest`. Two iterations:
#
#   Iteration 1 (case 2, env-supplied passphrase):
#     - wrap with SANCTUARY_PASSPHRASE set
#     - assert v1.1 endpoints all 200
#     - assert ~/.claude.json carries SANCTUARY_FORTRESS_PATH (Finding W)
#     - NEGATIVE: assert NO passphrase-backup.txt written
#     - NEGATIVE: assert NO disclosure banner in wrap stderr
#
#   Iteration 2 (case 3, Sanctuary-generated passphrase):
#     - wrap with NO SANCTUARY_PASSPHRASE set, no --passphrase flag
#     - POSITIVE: assert passphrase-backup.txt exists at mode 0600
#     - POSITIVE: assert disclosure banner header present in wrap stderr
#     - POSITIVE: assert backup-file content contains the off-host warning
#
# Both iterations must PASS for overall PASS.
#
# Usage (from a developer Mac with the v1.1.3 tag built):
#
#   bash scripts/published-tarball-smoke-2026-04-26.sh
#
# Exit code: 0 on all checks pass; non-zero on any failure (do NOT
# promote `latest` if non-zero).
#
# Requirements: bash, curl, jq, node 18+, stat. Run on macOS or Linux.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SERVER_DIR="${REPO_ROOT}/server"
SMOKE_ROOT=""
WRAP_PIDS=()

cleanup() {
  for pid in "${WRAP_PIDS[@]:-}"; do
    if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
      wait "${pid}" 2>/dev/null || true
    fi
  done
  if [[ -n "${SMOKE_ROOT}" ]] && [[ -d "${SMOKE_ROOT}" ]]; then
    rm -rf "${SMOKE_ROOT}"
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
require stat

# Cross-platform stat for octal mode bits. macOS = "stat -f %OLp"; Linux =
# "stat -c %a". Returns the three-digit permission bits without leading 0.
mode_bits() {
  local path="$1"
  if stat -f '%OLp' "${path}" >/dev/null 2>&1; then
    stat -f '%OLp' "${path}"
  else
    stat -c '%a' "${path}"
  fi
}

echo "==> Rebuilding dist/ from current source"
# CRITICAL: npm pack does NOT trigger prepublishOnly, so dist/ would
# otherwise carry whatever was last built (likely a stale prior version).
# Always rebuild here so the tarball reflects current source. Caught a
# real promotion-blocker on 2026-04-26 (smoke against a v1.1.2-labeled
# tarball that still contained v1.1.1 dist output).
cd "${SERVER_DIR}"
npm run build --silent

echo "==> Building tarball from ${SERVER_DIR}"
TARBALL=$(npm pack --silent | tail -1)
TARBALL_ABS="${SERVER_DIR}/${TARBALL}"
[[ -f "${TARBALL_ABS}" ]] || {
  echo "ERROR: tarball not produced at ${TARBALL_ABS}" >&2
  exit 2
}
echo "    Built: ${TARBALL}"

SMOKE_ROOT=$(mktemp -d -t v1_1_3_smoke_XXXXXXXX)

# Shared install dir reused by both iterations: tarball install only needs
# to happen once; each iteration gets its own HOME + fortress.
INSTALL_DIR="${SMOKE_ROOT}/install"
mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"
npm init -y >/dev/null
npm install --no-audit --no-fund --silent "${TARBALL_ABS}"
SANCTUARY_BIN="${INSTALL_DIR}/node_modules/.bin/sanctuary"
[[ -x "${SANCTUARY_BIN}" ]] || {
  echo "ERROR: sanctuary binary not found at ${SANCTUARY_BIN}" >&2
  exit 2
}

overall_fail=0

# Run a wrap iteration with caller-controlled env + flag set, then probe
# the v1.1 endpoints + run the supplied disclosure-assertion callback.
# Args:
#   $1 label (used in PIDs + log paths)
#   $2 use_env_passphrase (0 or 1)
#   $3 expect_disclosure (0 or 1)
run_iteration() {
  local label="$1"
  local use_env_passphrase="$2"
  local expect_disclosure="$3"

  local iter_home="${SMOKE_ROOT}/${label}-home"
  local iter_fortress="${SMOKE_ROOT}/${label}-fortress"
  mkdir -p "${iter_home}" "${iter_fortress}"
  local wrap_log="${iter_home}/wrap.log"

  echo
  echo "==> [${label}] Running sanctuary wrap"
  if [[ "${use_env_passphrase}" == "1" ]]; then
    HOME="${iter_home}" \
    SANCTUARY_PASSPHRASE="smoke-test-passphrase-do-not-use-in-prod-${label}" \
    SANCTUARY_DASHBOARD_AUTH_TOKEN="smoke-token-${label}" \
      "${SANCTUARY_BIN}" wrap --claude-code --fortress "${iter_fortress}" --no-open \
      > "${wrap_log}" 2>&1 &
  else
    # Case 3: NO env passphrase, NO --passphrase flag. Sanctuary generates.
    # Unset SANCTUARY_PASSPHRASE explicitly so a developer with one in
    # their shell does not contaminate the iteration.
    HOME="${iter_home}" \
    SANCTUARY_DASHBOARD_AUTH_TOKEN="smoke-token-${label}" \
    env -u SANCTUARY_PASSPHRASE \
      "${SANCTUARY_BIN}" wrap --claude-code --fortress "${iter_fortress}" --no-open \
      > "${wrap_log}" 2>&1 &
  fi
  local wrap_pid=$!
  WRAP_PIDS+=("${wrap_pid}")

  # Give wrap up to 30s to print the URL + token + bind the dashboard.
  local url=""
  local i
  for i in $(seq 1 30); do
    if grep -q "Sovereignty Dashboard running" "${wrap_log}" 2>/dev/null; then
      url=$(grep -oE 'http://127\.0\.0\.1:[0-9]+\?token=[A-Za-z0-9_-]+' "${wrap_log}" | head -1)
      break
    fi
    sleep 1
  done

  if [[ -z "${url}" ]]; then
    echo "    FAIL: [${label}] wrap did not print a tokenized dashboard URL within 30s." >&2
    echo "    wrap.log:" >&2
    cat "${wrap_log}" >&2
    overall_fail=1
    return
  fi

  local base_url="${url%%\?*}"
  local query="${url#*\?}"
  echo "    Dashboard URL: ${base_url} (token captured)"

  # Probe v1.1 + legacy endpoints.
  local probe_path probe_label code
  for entry in \
      "/v1.1|v1.1 dashboard HTML" \
      "/api/hub/agents|v1.1 hub agents API" \
      "/api/identities|Finding E /api/identities alias" \
      "/|legacy v1.0 dashboard"; do
    probe_path="${entry%%|*}"
    probe_label="${entry#*|}"
    code=$(curl -sS -o /dev/null -w "%{http_code}" "${base_url}${probe_path}?${query}")
    if [[ "${code}" == "200" ]]; then
      echo "    PASS: [${label}] ${probe_label} (${probe_path}) -> 200"
    else
      echo "    FAIL: [${label}] ${probe_label} (${probe_path}) -> ${code} (expected 200)" >&2
      overall_fail=1
    fi
  done

  # Finding W check: ~/.claude.json carries SANCTUARY_FORTRESS_PATH.
  local claude_json="${iter_home}/.claude.json"
  if [[ ! -f "${claude_json}" ]]; then
    echo "    FAIL: [${label}] ${claude_json} not written by wrap" >&2
    overall_fail=1
  else
    local persisted expected_abs
    persisted=$(jq -r '.mcpServers.sanctuary.env.SANCTUARY_FORTRESS_PATH // empty' "${claude_json}")
    expected_abs=$(cd "${iter_fortress}" 2>/dev/null && pwd || echo "${iter_fortress}")
    if [[ "${persisted}" == "${expected_abs}" ]]; then
      echo "    PASS: [${label}] SANCTUARY_FORTRESS_PATH = ${persisted}"
    else
      echo "    FAIL: [${label}] SANCTUARY_FORTRESS_PATH mismatch" >&2
      echo "         expected: ${expected_abs}" >&2
      echo "         got:      ${persisted:-<unset>}" >&2
      overall_fail=1
    fi
  fi

  # Finding X check: passphrase disclosure on case 3, no disclosure on cases 1 + 2.
  local backup_file="${iter_fortress}/passphrase-backup.txt"
  local banner_marker="SANCTUARY: First Run, Passphrase Generated"
  if [[ "${expect_disclosure}" == "1" ]]; then
    if [[ -f "${backup_file}" ]]; then
      echo "    PASS: [${label}] passphrase-backup.txt exists"
      local mode
      mode=$(mode_bits "${backup_file}")
      if [[ "${mode}" == "600" ]]; then
        echo "    PASS: [${label}] passphrase-backup.txt mode 0600"
      else
        echo "    FAIL: [${label}] passphrase-backup.txt mode ${mode} (expected 600)" >&2
        overall_fail=1
      fi
      if grep -q "DO NOT COMMIT, DO NOT EMAIL, MOVE OFF-HOST IMMEDIATELY" "${backup_file}"; then
        echo "    PASS: [${label}] passphrase-backup.txt contains off-host warning"
      else
        echo "    FAIL: [${label}] passphrase-backup.txt missing off-host warning" >&2
        overall_fail=1
      fi
    else
      echo "    FAIL: [${label}] passphrase-backup.txt NOT written (expected on case 3)" >&2
      overall_fail=1
    fi
    if grep -qF "${banner_marker}" "${wrap_log}"; then
      echo "    PASS: [${label}] disclosure banner present in wrap stderr"
    else
      echo "    FAIL: [${label}] disclosure banner missing from wrap stderr" >&2
      overall_fail=1
    fi
  else
    if [[ -f "${backup_file}" ]]; then
      echo "    FAIL: [${label}] passphrase-backup.txt exists (must NOT on env/flag-supplied)" >&2
      overall_fail=1
    else
      echo "    PASS: [${label}] no passphrase-backup.txt (env/flag-supplied)"
    fi
    if grep -qF "${banner_marker}" "${wrap_log}"; then
      echo "    FAIL: [${label}] disclosure banner present (must NOT on env/flag-supplied)" >&2
      overall_fail=1
    else
      echo "    PASS: [${label}] no disclosure banner (env/flag-supplied)"
    fi
  fi

  # Tear down this iteration's wrap subprocess so the next iteration can
  # bind its own port without contention. SIGTERM first; the wrap process
  # owns dashboard + child keychain calls and may not exit instantly under
  # SIGTERM, so escalate to SIGKILL after a short grace window. Bash
  # builtin `wait` is unbounded, which would hang the script if the child
  # graceful-shutdown path stalls; the bounded poll below is the fix.
  if kill -0 "${wrap_pid}" 2>/dev/null; then
    kill "${wrap_pid}" 2>/dev/null || true
    local grace
    for grace in 1 2 3; do
      if ! kill -0 "${wrap_pid}" 2>/dev/null; then break; fi
      sleep 1
    done
    if kill -0 "${wrap_pid}" 2>/dev/null; then
      kill -KILL "${wrap_pid}" 2>/dev/null || true
    fi
    # Reap the zombie without blocking; redirect noise from `wait`.
    wait "${wrap_pid}" 2>/dev/null || true
  fi
}

# Iteration 1: case 2 (env-supplied passphrase, no disclosure expected).
run_iteration "iter1-env" 1 0

# Iteration 2: case 3 (Sanctuary-generated passphrase, disclosure expected).
run_iteration "iter2-generated" 0 1

echo
if [[ "${overall_fail}" == "0" ]]; then
  echo "==> v1.1.3 pre-promote smoke: PASS. Safe to flip dist-tag to latest."
  exit 0
else
  echo "==> v1.1.3 pre-promote smoke: FAIL. Do NOT promote latest." >&2
  echo "    SMOKE_ROOT (preserved for triage): ${SMOKE_ROOT}" >&2
  trap - EXIT
  exit 1
fi
