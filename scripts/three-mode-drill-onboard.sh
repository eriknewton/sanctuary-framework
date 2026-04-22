#!/usr/bin/env bash
# Sanctuary Federation Protocol v0.1 — Three-Mode Acceptance Drill
# Pilot operator onboarding script.
#
# Runs the full drill end-to-end: creates the scratch .sanctuary-drill/
# directory tree, seeds the fortress-master + root principal + per-node
# materials, launches three node processes on distinct loopback multiaddrs,
# and exits 0 when all three nodes report roster steady-state (every peer
# seen as active).
#
# See scripts/three-mode-drill-README.md for the operator-facing walkthrough.
#
# Copyright 2026 Erik Newton — SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────
# The drill is confined to a scratch dir the script creates. Tear down with:
#   rm -rf .sanctuary-drill/
# Override DRILL_DIR to run multiple concurrent drills in isolation.
DRILL_DIR="${DRILL_DIR:-.sanctuary-drill}"
STEADY_STATE_TIMEOUT_S="${STEADY_STATE_TIMEOUT_S:-60}"

# Compute the worktree root and the server/ subdir — the TS runtime lives at
# `server/scripts/three-mode-drill/`.
WORKTREE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_DIR="$WORKTREE_ROOT/server"
ABS_DRILL_DIR="$WORKTREE_ROOT/$DRILL_DIR"

if [[ ! -d "$SERVER_DIR" ]]; then
  echo "three-mode-drill: server/ directory not found at $SERVER_DIR" >&2
  exit 1
fi
if [[ ! -d "$SERVER_DIR/node_modules" ]]; then
  echo "three-mode-drill: server dependencies missing. Run:"
  echo "  cd server && npm install"
  exit 1
fi

echo "three-mode-drill: worktree=$WORKTREE_ROOT"
echo "three-mode-drill: drill dir=$ABS_DRILL_DIR"

# ── Clean + seed ──────────────────────────────────────────────────────────
if [[ -d "$ABS_DRILL_DIR" ]]; then
  echo "three-mode-drill: removing prior drill state at $ABS_DRILL_DIR"
  rm -rf "$ABS_DRILL_DIR"
fi
mkdir -p "$ABS_DRILL_DIR"

cd "$SERVER_DIR"
echo "three-mode-drill: seeding fortress materials..."
npx tsx scripts/three-mode-drill/seed.ts "$ABS_DRILL_DIR"

# ── Launch three node processes ───────────────────────────────────────────
# Node A first (no static peers). B dials A. C dials A and B.
LOG_DIR="$ABS_DRILL_DIR/logs"
mkdir -p "$LOG_DIR"

pids=()

cleanup() {
  echo ""
  echo "three-mode-drill: tearing down node processes..."
  for pid in "${pids[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  # Give processes 2 seconds to exit gracefully.
  sleep 2
  for pid in "${pids[@]:-}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  done
}
trap cleanup EXIT INT TERM

launch_node() {
  local role="$1"
  # Redirect stdout+stderr to a log file so the orchestrator's console stays
  # clean. Operator can `tail -f $LOG_DIR/NODE_X.log` to watch a given node.
  npx tsx scripts/three-mode-drill/node.ts "$ABS_DRILL_DIR" "$role" \
    > "$LOG_DIR/node$role.log" 2>&1 &
  pids+=("$!")
  echo "three-mode-drill: node $role started (pid=$!, log=$LOG_DIR/node$role.log)"
}

launch_node A
# Wait for A's multiaddr to appear before starting B.
while [[ ! -s "$ABS_DRILL_DIR/nodeA/multiaddr.txt" ]]; do sleep 0.2; done
launch_node B
while [[ ! -s "$ABS_DRILL_DIR/nodeB/multiaddr.txt" ]]; do sleep 0.2; done
launch_node C
while [[ ! -s "$ABS_DRILL_DIR/nodeC/multiaddr.txt" ]]; do sleep 0.2; done

echo "three-mode-drill: all three nodes listening. Waiting for steady state..."

# ── Wait for steady state ─────────────────────────────────────────────────
# Each node writes JSON status to status/ROLE.json every second. Steady
# state = all three nodes report roster_size=3 AND every peer presence
# reads "active".
read_roster_size() {
  local role="$1"
  local status="$ABS_DRILL_DIR/status/$role.json"
  [[ -f "$status" ]] || { echo 0; return; }
  # Keep the dependency footprint small — read with Node rather than
  # requiring jq at the operator's shell.
  node -e "const j=require('$status');process.stdout.write(String(j.roster_size||0))" 2>/dev/null || echo 0
}
all_peers_active() {
  local role="$1"
  local status="$ABS_DRILL_DIR/status/$role.json"
  [[ -f "$status" ]] || return 1
  node -e "
    const j=require('$status');
    const presence=j.presence||{};
    const peers=['A','B','C'].filter(x=>x!=='$role');
    const allActive=peers.every(p=>presence[p]==='active');
    process.exit(allActive?0:1);
  " 2>/dev/null
}

elapsed=0
while (( elapsed < STEADY_STATE_TIMEOUT_S )); do
  aSize=$(read_roster_size A)
  bSize=$(read_roster_size B)
  cSize=$(read_roster_size C)
  if [[ "$aSize" == "3" && "$bSize" == "3" && "$cSize" == "3" ]]; then
    if all_peers_active A && all_peers_active B && all_peers_active C; then
      echo ""
      echo "three-mode-drill: STEADY STATE ACHIEVED (elapsed ~${elapsed}s)"
      echo "  node A (local)          roster_size=3 | all peers active"
      echo "  node B (operator_cloud) roster_size=3 | all peers active"
      echo "  node C (sovereign_tee)  roster_size=3 | all peers active"
      echo ""
      echo "Drill materials at: $ABS_DRILL_DIR"
      echo "Tear down with:    rm -rf $ABS_DRILL_DIR"
      exit 0
    fi
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done

echo ""
echo "three-mode-drill: TIMEOUT after ${STEADY_STATE_TIMEOUT_S}s without steady state" >&2
echo "  node A: roster_size=$(read_roster_size A)"
echo "  node B: roster_size=$(read_roster_size B)"
echo "  node C: roster_size=$(read_roster_size C)"
echo ""
echo "Check logs: $LOG_DIR"
exit 1
