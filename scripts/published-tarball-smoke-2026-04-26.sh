#!/usr/bin/env bash
# Sanctuary v1.1.5 Pre-Promote Smoke (Findings V + W + X + Y + Z + AA)
#
# v1.1.2 closed Finding V (v1.1 routes mounted on the wrap-auto
# dashboard) and Finding W (SANCTUARY_FORTRESS_PATH persisted into
# `~/.claude.json`). v1.1.3 closed Finding X (passphrase disclosure on
# case 3 fresh wraps). v1.1.4 closed Finding Y (v1.1 SPA bootstrap +
# JSON.parse crash on HTML-entity-encoded config). v1.1.5 closes Z
# (`/api/hub/agents` was structurally empty after wrap because v1.1.1
# deferred persistence to v1.2; wrap now writes a fortress-side agent
# record that `buildV11Bindings()` rehydrates from disk) and AA
# (`sanctuary wrap --no-dashboard` skips the per-call dashboard spawn
# so operators can run one persistent dashboard alongside many wraps).
#
# This script proves all bug classes are GONE in the to-be-published
# tarball before the dist-tag flips to `latest`. Four iterations:
#
#   Iteration 1 (case 2, env-supplied passphrase):
#     - wrap with SANCTUARY_PASSPHRASE set
#     - assert v1.1 endpoints all 200
#     - assert ~/.claude.json carries SANCTUARY_FORTRESS_PATH (W)
#     - assert /api/hub/agents data.agents.length >= 1 (Z)
#     - NEGATIVE: assert NO passphrase-backup.txt written
#     - NEGATIVE: assert NO disclosure banner in wrap stderr
#
#   Iteration 2 (case 3, Sanctuary-generated passphrase):
#     - wrap with NO SANCTUARY_PASSPHRASE set, no --passphrase flag
#     - POSITIVE: assert passphrase-backup.txt exists at mode 0600
#     - POSITIVE: assert disclosure banner header present in wrap stderr
#     - POSITIVE: assert backup-file content contains the off-host warning
#     - assert /api/hub/agents data.agents.length >= 1 (Z)
#
#   Iteration 3 (--no-dashboard, AA):
#     - wrap with --no-dashboard against a fresh fortress
#     - assert wrap exit code 0
#     - assert no Sovereignty Dashboard URL printed on stderr
#     - assert state/_hub/local-agents.json written with one record
#       (Z fix preserved on the no-dashboard path)
#     - assert "Dashboard spawn skipped per --no-dashboard" line on stderr
#
#   Iteration 4 (standalone dashboard + --no-dashboard wrap, AA + Z together):
#     - sanctuary dashboard --fortress <path> &
#     - sanctuary wrap --claude-code --fortress <same path> --no-dashboard
#     - curl /api/hub/agents against the standalone dashboard
#     - assert response contains the wrapped harness (rehydration works)
#
# All iterations must PASS for overall PASS.
#
# Usage (from a developer Mac with the v1.1.5-hotfix branch built):
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

  # Finding Z check: /api/hub/agents must return a non-empty agents
  # array after wrap. Pre-v1.1.5 this returned `data.agents = []` even
  # on a freshly wrapped fortress because the in-memory registry was
  # constructed empty on every boot and wrap had no persistence write.
  # v1.1.5 wrap writes <storagePath>/state/_hub/local-agents.json and
  # buildV11Bindings rehydrates from it.
  local agents_json agents_count agents_first_harness
  agents_json=$(curl -sS "${base_url}/api/hub/agents?${query}")
  agents_count=$(printf '%s' "${agents_json}" \
    | jq -r '.data.agents | length' 2>/dev/null || echo "0")
  if [[ "${agents_count}" -ge "1" ]]; then
    agents_first_harness=$(printf '%s' "${agents_json}" \
      | jq -r '.data.agents[0].harness // "<missing>"')
    echo "    PASS: [${label}] /api/hub/agents reports ${agents_count} wrapped harness(es) (first: ${agents_first_harness})"
  else
    echo "    FAIL: [${label}] /api/hub/agents data.agents.length = ${agents_count} (expected >= 1)" >&2
    echo "         response: ${agents_json:0:200}" >&2
    overall_fail=1
  fi

  local hub_file="${iter_fortress}/state/_hub/local-agents.json"
  if [[ -f "${hub_file}" ]]; then
    local hub_mode
    hub_mode=$(mode_bits "${hub_file}")
    if [[ "${hub_mode}" == "600" ]]; then
      echo "    PASS: [${label}] state/_hub/local-agents.json mode 0600"
    else
      echo "    FAIL: [${label}] state/_hub/local-agents.json mode ${hub_mode} (expected 600)" >&2
      overall_fail=1
    fi
  else
    echo "    FAIL: [${label}] state/_hub/local-agents.json not written by wrap" >&2
    overall_fail=1
  fi

  # Finding Y check: served /v1.1 HTML's `<script id="dashboard-config">`
  # block must parse as JSON. v1.1.3 emitted HTML-entity-encoded JSON
  # (`&quot;` instead of `"`) inside a `<script type="application/json">`
  # block; HTML parses script content as RAWTEXT (no entity decoding) so
  # the client's JSON.parse(cfgEl.textContent) crashed before any XHR.
  # Catches the class against the actual published binary, not just the
  # unit suite.
  local v11_html config_block parse_log
  v11_html=$(curl -sS "${base_url}/v1.1?${query}")
  if [[ -z "${v11_html}" ]]; then
    echo "    FAIL: [${label}] /v1.1 returned empty body" >&2
    overall_fail=1
  else
    config_block=$(printf '%s' "${v11_html}" \
      | sed -n 's|.*<script id="dashboard-config" type="application/json">\(.*\)</script>.*|\1|p' \
      | head -1)
    if [[ -z "${config_block}" ]]; then
      echo "    FAIL: [${label}] dashboard-config script block not found in /v1.1 HTML" >&2
      overall_fail=1
    else
      parse_log=$(printf '%s' "${config_block}" \
        | node -e 'try { const c = require("fs").readFileSync(0, "utf8"); const o = JSON.parse(c); if (typeof o.authToken !== "string") { console.error("authToken missing or non-string"); process.exit(3); } if (typeof o.fortressId !== "string") { console.error("fortressId missing or non-string"); process.exit(3); } process.exit(0); } catch (e) { console.error(e.message); process.exit(2); }' 2>&1) \
        && parse_status=0 || parse_status=$?
      if [[ "${parse_status}" == "0" ]]; then
        echo "    PASS: [${label}] /v1.1 dashboard-config parses as JSON with expected keys"
      else
        echo "    FAIL: [${label}] /v1.1 dashboard-config did not parse as JSON (status ${parse_status})" >&2
        echo "         parser stderr: ${parse_log}" >&2
        echo "         block (first 200 chars): ${config_block:0:200}" >&2
        overall_fail=1
      fi
    fi
  fi

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

# Iteration 3 (Finding AA): wrap with --no-dashboard. Asserts no
# dashboard URL printed, exit code 0, agent record persisted, and the
# persistent-dashboard skip note appears on stderr.
run_no_dashboard_iteration() {
  local label="iter3-no-dashboard"
  local iter_home="${SMOKE_ROOT}/${label}-home"
  local iter_fortress="${SMOKE_ROOT}/${label}-fortress"
  mkdir -p "${iter_home}" "${iter_fortress}"
  local wrap_log="${iter_home}/wrap.log"

  echo
  echo "==> [${label}] Running sanctuary wrap --no-dashboard"
  local wrap_exit=0
  HOME="${iter_home}" \
  SANCTUARY_PASSPHRASE="smoke-test-passphrase-do-not-use-in-prod-${label}" \
    "${SANCTUARY_BIN}" wrap --claude-code --fortress "${iter_fortress}" \
      --no-dashboard --no-open \
      > "${wrap_log}" 2>&1 || wrap_exit=$?

  if [[ "${wrap_exit}" == "0" ]]; then
    echo "    PASS: [${label}] wrap exit code 0"
  else
    echo "    FAIL: [${label}] wrap exit code ${wrap_exit}" >&2
    cat "${wrap_log}" >&2
    overall_fail=1
    return
  fi

  if grep -q "Sovereignty Dashboard running at" "${wrap_log}" 2>/dev/null; then
    echo "    FAIL: [${label}] dashboard URL printed (must NOT on --no-dashboard)" >&2
    overall_fail=1
  else
    echo "    PASS: [${label}] no dashboard URL printed"
  fi

  if grep -q "Dashboard spawn skipped per --no-dashboard" "${wrap_log}" 2>/dev/null; then
    echo "    PASS: [${label}] persistent-dashboard skip note present"
  else
    echo "    FAIL: [${label}] persistent-dashboard skip note missing" >&2
    overall_fail=1
  fi

  local hub_file="${iter_fortress}/state/_hub/local-agents.json"
  if [[ ! -f "${hub_file}" ]]; then
    echo "    FAIL: [${label}] state/_hub/local-agents.json not written" >&2
    overall_fail=1
    return
  fi
  local persisted_count
  persisted_count=$(jq -r '.agents | length' "${hub_file}" 2>/dev/null || echo "0")
  if [[ "${persisted_count}" == "1" ]]; then
    local persisted_harness
    persisted_harness=$(jq -r '.agents[0].harness // "<missing>"' "${hub_file}")
    echo "    PASS: [${label}] state/_hub/local-agents.json has 1 record (harness: ${persisted_harness})"
  else
    echo "    FAIL: [${label}] state/_hub/local-agents.json has ${persisted_count} records (expected 1)" >&2
    overall_fail=1
  fi
}

# Iteration 4 (Findings AA + Z together): standalone `sanctuary dashboard`
# alongside `sanctuary wrap --no-dashboard` exercises the canonical
# operator-clean flow. The standalone dashboard rehydrates the agent
# registry from the hub file each wrap writes.
run_standalone_plus_wrap_iteration() {
  local label="iter4-standalone-plus-wrap"
  local iter_home="${SMOKE_ROOT}/${label}-home"
  local iter_fortress="${SMOKE_ROOT}/${label}-fortress"
  mkdir -p "${iter_home}" "${iter_fortress}"
  local dashboard_log="${iter_home}/dashboard.log"
  local wrap_log="${iter_home}/wrap.log"

  echo
  echo "==> [${label}] Starting persistent sanctuary dashboard"
  HOME="${iter_home}" \
  SANCTUARY_PASSPHRASE="smoke-test-passphrase-do-not-use-in-prod-${label}" \
  SANCTUARY_DASHBOARD_AUTH_TOKEN="smoke-token-${label}" \
    "${SANCTUARY_BIN}" dashboard --fortress "${iter_fortress}" --no-open \
      > "${dashboard_log}" 2>&1 &
  local dash_pid=$!
  WRAP_PIDS+=("${dash_pid}")

  # Wait up to 30s for the standalone dashboard to bind.
  local dash_url=""
  local i
  for i in $(seq 1 30); do
    if grep -q "Listening:" "${dashboard_log}" 2>/dev/null; then
      dash_url=$(grep -oE 'http://127\.0\.0\.1:[0-9]+' "${dashboard_log}" | head -1)
      break
    fi
    sleep 1
  done

  if [[ -z "${dash_url}" ]]; then
    echo "    FAIL: [${label}] standalone dashboard did not bind within 30s" >&2
    cat "${dashboard_log}" >&2
    overall_fail=1
    return
  fi
  echo "    Standalone dashboard: ${dash_url}"

  echo "    Running sanctuary wrap --no-dashboard against same fortress"
  HOME="${iter_home}" \
  SANCTUARY_PASSPHRASE="smoke-test-passphrase-do-not-use-in-prod-${label}" \
    "${SANCTUARY_BIN}" wrap --claude-code --fortress "${iter_fortress}" \
      --no-dashboard --no-open \
      > "${wrap_log}" 2>&1 || {
    echo "    FAIL: [${label}] wrap --no-dashboard failed" >&2
    cat "${wrap_log}" >&2
    overall_fail=1
    return
  }

  # The standalone dashboard's hub registry was constructed at boot,
  # before wrap wrote the local-agents.json file. Restart the standalone
  # dashboard so its in-memory registry rehydrates. (v1.1.5 rehydration
  # happens at construction; live re-read is a v1.1.x backlog item.)
  if kill -0 "${dash_pid}" 2>/dev/null; then
    kill "${dash_pid}" 2>/dev/null || true
    local grace
    for grace in 1 2 3; do
      if ! kill -0 "${dash_pid}" 2>/dev/null; then break; fi
      sleep 1
    done
    if kill -0 "${dash_pid}" 2>/dev/null; then
      kill -KILL "${dash_pid}" 2>/dev/null || true
    fi
    wait "${dash_pid}" 2>/dev/null || true
  fi
  : > "${dashboard_log}"

  HOME="${iter_home}" \
  SANCTUARY_PASSPHRASE="smoke-test-passphrase-do-not-use-in-prod-${label}" \
  SANCTUARY_DASHBOARD_AUTH_TOKEN="smoke-token-${label}" \
    "${SANCTUARY_BIN}" dashboard --fortress "${iter_fortress}" --no-open \
      > "${dashboard_log}" 2>&1 &
  local dash_pid2=$!
  WRAP_PIDS+=("${dash_pid2}")

  dash_url=""
  for i in $(seq 1 30); do
    if grep -q "Listening:" "${dashboard_log}" 2>/dev/null; then
      dash_url=$(grep -oE 'http://127\.0\.0\.1:[0-9]+' "${dashboard_log}" | head -1)
      break
    fi
    sleep 1
  done

  if [[ -z "${dash_url}" ]]; then
    echo "    FAIL: [${label}] standalone dashboard restart did not bind within 30s" >&2
    cat "${dashboard_log}" >&2
    overall_fail=1
    return
  fi

  if grep -q "Local agents loaded:" "${dashboard_log}" 2>/dev/null; then
    local loaded_line
    loaded_line=$(grep "Local agents loaded:" "${dashboard_log}" | head -1)
    echo "    PASS: [${label}] standalone dashboard logged: ${loaded_line}"
  else
    echo "    FAIL: [${label}] 'Local agents loaded:' line missing from standalone dashboard log" >&2
    overall_fail=1
  fi

  local agents_json agents_count
  agents_json=$(curl -sS -H "Authorization: Bearer smoke-token-${label}" "${dash_url}/api/hub/agents")
  agents_count=$(printf '%s' "${agents_json}" \
    | jq -r '.data.agents | length' 2>/dev/null || echo "0")
  if [[ "${agents_count}" -ge "1" ]]; then
    echo "    PASS: [${label}] standalone /api/hub/agents reports ${agents_count} wrapped harness(es) (rehydration works)"
  else
    echo "    FAIL: [${label}] standalone /api/hub/agents data.agents.length = ${agents_count} (expected >= 1)" >&2
    echo "         response: ${agents_json:0:200}" >&2
    overall_fail=1
  fi
}

# Iteration 1: case 2 (env-supplied passphrase, no disclosure expected).
run_iteration "iter1-env" 1 0

# Iteration 2: case 3 (Sanctuary-generated passphrase, disclosure expected).
run_iteration "iter2-generated" 0 1

# Iteration 3 (Finding AA): --no-dashboard.
run_no_dashboard_iteration

# Iteration 4 (Findings AA + Z together): standalone + --no-dashboard.
run_standalone_plus_wrap_iteration

echo
if [[ "${overall_fail}" == "0" ]]; then
  echo "==> v1.1.5 pre-promote smoke: PASS. Safe to flip dist-tag to latest."
  exit 0
else
  echo "==> v1.1.5 pre-promote smoke: FAIL. Do NOT promote latest." >&2
  echo "    SMOKE_ROOT (preserved for triage): ${SMOKE_ROOT}" >&2
  trap - EXIT
  exit 1
fi
