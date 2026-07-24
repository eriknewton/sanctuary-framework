#!/usr/bin/env bash
#
# run-loop.sh - the autonomous drill loop.
#
# Runs the drill ladder N times unattended and captures everything. There is no
# model in this loop: it is deterministic bash plus expect, so it does not need
# any API credential and nothing about it depends on a login session staying
# alive. Intelligence enters afterwards, reading the artifacts in the morning.
#
#   preflight -> provision + arm -> probe battery -> teardown -> verify-clean -> capture
#
# EXECUTION POLICY: MAXIMUM FORWARD PROGRESS
#
# An iteration never halts at the first bug. Each ladder step declares its
# preconditions; when a step fails, only the steps whose preconditions are now
# unmeetable are skipped, and every independent step is still attempted. The
# point is to harvest as many DISTINCT bugs per night as a night can hold.
#
# Findings downstream of a failure are labeled `tainted-by:<step>`, because
# post-failure state has misled diagnosis for entire sessions before. An
# untainted finding is a bug; a tainted one is a lead.
#
# THE TWO STOP-THE-NIGHT EXCEPTIONS
#
#   1. a teardown or verify-clean failure. Continuing past a dirty teardown
#      risks wedging the host and every later iteration is born tainted.
#   2. any safety-rail trip. There is no "recover and continue" past a rail.
#
# Usage:
#   run-loop.sh --mode sweep|soak|reboot --iterations N \
#     --operator-account <a> --agent-account <a> --agent-uid <n> \
#     [--evidence-root <dir>] [--passphrase-file <f>] [--build-sha <sha>] \
#     [--stop-at-first-divergence]
#
# --stop-at-first-divergence is an INTERACTIVE debugging flag. It is never used
# by the scheduled run; a nightly loop that stops at the first bug wastes the
# night.

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(CDPATH='' cd -P -- "$HERE/.." && pwd -P)"
REPO="$(CDPATH='' cd -P -- "$ROOT/../.." && pwd -P)"
# shellcheck source=../lib/rails.sh
. "$ROOT/lib/rails.sh"

INSTALLED_WRAPPER='/usr/local/sbin/sanctuary-drill-wrapper'

die() {
  printf 'run-loop: %s\n' "$*" >&2
  exit 2
}

# A safety-rail trip is stop-the-night, and it is loud.
rail_stop() {
  printf 'LOOP=STOP reason=safety-rail detail=%s\n' "$*"
  printf 'run-loop: SAFETY RAIL TRIPPED: %s\n' "$*" >&2
  exit 3
}

MODE='sweep'
ITERATIONS=1
OPERATOR=''
AGENT=''
AGENT_UID_IN=''
EVIDENCE_ROOT=''
PASSFILE=''
BUILD_SHA=''
STOP_FIRST=''
OPERATOR_HOME="${HOME:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)                     MODE="${2:-}"; shift 2 ;;
    --iterations)               ITERATIONS="${2:-}"; shift 2 ;;
    --operator-account)         OPERATOR="${2:-}"; shift 2 ;;
    --agent-account)            AGENT="${2:-}"; shift 2 ;;
    --agent-uid)                AGENT_UID_IN="${2:-}"; shift 2 ;;
    --evidence-root)            EVIDENCE_ROOT="${2:-}"; shift 2 ;;
    --passphrase-file)          PASSFILE="${2:-}"; shift 2 ;;
    --build-sha)                BUILD_SHA="${2:-}"; shift 2 ;;
    --home)                     OPERATOR_HOME="${2:-}"; shift 2 ;;
    --stop-at-first-divergence) STOP_FIRST='yes'; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

case "$MODE" in
  sweep|soak|reboot) ;;
  *) die "unknown mode: $MODE (expected sweep, soak or reboot)" ;;
esac
case "$ITERATIONS" in
  ''|*[!0-9]*) die "--iterations must be a positive integer: $ITERATIONS" ;;
esac
if [ "$ITERATIONS" -lt 1 ]; then die '--iterations must be at least 1'; fi
[ -n "$OPERATOR_HOME" ] || die 'cannot determine the operator home directory'

# ---------------------------------------------------------------------------
# rails, before anything else happens
# ---------------------------------------------------------------------------

# HOST. Deny-first, compiled-in allowlist, fail closed. Several observed
# identities so a machine answering to the daily driver's name under any of
# them is refused.
rails_assert_host_allowed \
  "$(hostname -s 2>/dev/null || printf '')" \
  "$(hostname -f 2>/dev/null || hostname 2>/dev/null || printf '')" \
  || rail_stop "host rail refused $(hostname -s 2>/dev/null || printf 'unknown')"

OPERATOR_UID="$(rails_assert_non_root_account operator "$OPERATOR")" \
  || rail_stop "operator account rejected: $OPERATOR"
[ -n "$OPERATOR_UID" ] || rail_stop 'empty operator uid after rail'
AGENT_UID="$(rails_assert_account_uid agent "$AGENT" "$AGENT_UID_IN")" \
  || rail_stop "agent account rejected: $AGENT"
[ -n "$AGENT_UID" ] || rail_stop 'empty agent uid after rail'

if [ -n "$PASSFILE" ]; then
  rails_assert_secret_file_perms "$PASSFILE" "$OPERATOR" \
    || rail_stop "passphrase-file rail rejected: $PASSFILE"
fi

# WRAPPER INTEGRITY. Re-assemble from the repo, then require the repo, the
# committed hash and the INSTALLED file to agree. This is what catches both
# "you edited the repo and forgot to reinstall" and "someone edited the
# installed wrapper", and it runs before the loop can invoke it even once.
ASSEMBLED="$(mktemp "${TMPDIR:-/tmp}/sanctuary-drill-wrapper-check.XXXXXX")"
cleanup_assembled() { rm -f "$ASSEMBLED"; }
trap cleanup_assembled EXIT
"$ROOT/build-wrapper.sh" --stdout > "$ASSEMBLED" \
  || rail_stop 'could not re-assemble the wrapper from the repo'
rails_assert_wrapper_integrity "$ASSEMBLED" "$INSTALLED_WRAPPER" "$ROOT/wrapper.sha256" \
  || rail_stop 'wrapper integrity rail refused'

if [ -z "$BUILD_SHA" ]; then
  BUILD_SHA="$(git -C "$REPO" rev-parse HEAD 2>/dev/null || printf '')"
fi

STAMP="$(date +%Y%m%dT%H%M%S)"
if [ -z "$EVIDENCE_ROOT" ]; then
  EVIDENCE_ROOT="$OPERATOR_HOME/sanctuary-drill-loop-evidence/$STAMP"
fi
mkdir -p "$EVIDENCE_ROOT"
FINDINGS="$EVIDENCE_ROOT/FINDINGS.jsonl"
: > "$FINDINGS"

# LOOP LOCK. A scheduled run and an interactive drill must never interleave.
LOCK="$OPERATOR_HOME/.sanctuary-drill-loop.lock"
rails_lock_acquire "$LOCK" 60 || rail_stop "could not acquire the loop lock at $LOCK"
release_all() {
  rails_lock_release "$LOCK" 2>/dev/null || true
  cleanup_assembled
}
trap release_all EXIT

printf 'LOOP=START mode=%s iterations=%s build_sha=%s evidence=%s\n' \
  "$MODE" "$ITERATIONS" "${BUILD_SHA:-unknown}" "$EVIDENCE_ROOT"

# ---------------------------------------------------------------------------
# per-iteration ladder
# ---------------------------------------------------------------------------

json_escape() {
  # Minimal JSON string escaping for the fields we actually emit.
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g'
}

emit_finding() {
  # emit_finding <iteration> <step> <result> <taint> <detail> <artifacts>
  printf '{"iteration":%s,"step":"%s","result":"%s","tainted_by":"%s","detail":"%s","artifacts":"%s","build_sha":"%s","ts":"%s"}\n' \
    "$1" "$(json_escape "$2")" "$(json_escape "$3")" "$(json_escape "$4")" \
    "$(json_escape "$5")" "$(json_escape "$6")" "$(json_escape "${BUILD_SHA:-unknown}")" \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$FINDINGS"
}

ITER=1
NIGHT_STOPPED=''
TOTAL_FAILURES=0

while [ "$ITER" -le "$ITERATIONS" ]; do
  IEV="$EVIDENCE_ROOT/iteration-$ITER"
  mkdir -p "$IEV"
  printf 'LOOP=ITERATION n=%s evidence=%s\n' "$ITER" "$IEV"

  # A fresh disposable fortress per iteration, minted under the ONLY prefix the
  # rails allow, then re-asserted through the rail before anything uses it.
  STORAGE_IN="$OPERATOR_HOME/.sanctuary-loop-$STAMP-$ITER"
  STORAGE="$(rails_assert_disposable_storage "$OPERATOR_HOME" "$STORAGE_IN")" \
    || rail_stop "storage rail rejected the minted path: $STORAGE_IN"
  [ -n "$STORAGE" ] || rail_stop 'empty storage after rail'

  # Preconditions, tracked so a failed step only skips what genuinely depends
  # on it. `armed` gates the through-gate probes; nothing gates teardown.
  ARMED=''
  TAINT=''

  # --- step 1: preflight ---------------------------------------------------
  if "$HERE/preflight.sh" --storage "$STORAGE" --home "$OPERATOR_HOME" \
       --build-sha "$BUILD_SHA" --agent-uid "$AGENT_UID" \
       > "$IEV/preflight.log" 2>&1
  then
    emit_finding "$ITER" preflight PASS '' 'all preflight checks passed' "$IEV/preflight.log"
  else
    emit_finding "$ITER" preflight FAIL '' 'one or more preflight checks failed' "$IEV/preflight.log"
    TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
    TAINT='preflight'
    # A preflight failure is a finding, not a crash. The iteration aborts
    # cleanly rather than measuring a host we already know is wrong, but the
    # loop keeps going.
    if [ -n "$STOP_FIRST" ]; then NIGHT_STOPPED='preflight'; break; fi
    ITER=$((ITER + 1))
    continue
  fi

  # --- step 2: provision + arm --------------------------------------------
  if "$ROOT/expect/arm-expect.exp" \
       "$INSTALLED_WRAPPER" "$STORAGE" "$OPERATOR" "$AGENT" "$AGENT_UID" \
       > "$IEV/arm.log" 2>&1
  then
    ARMED='yes'
    emit_finding "$ITER" arm PASS "$TAINT" 'exclusive egress armed' "$IEV/arm.log"
  else
    emit_finding "$ITER" arm FAIL "$TAINT" 'arm did not complete' "$IEV/arm.log"
    TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
    if [ -z "$TAINT" ]; then TAINT='arm'; fi
  fi

  # --- step 3: probe battery ----------------------------------------------
  # Precondition: the gate is armed. Probing THROUGH a gate that never armed
  # produces cascade artifacts, not findings, so it is skipped and labeled.
  if [ -n "$ARMED" ]; then
    if "$HERE/run-probe-battery.sh" --storage "$STORAGE" --home "$OPERATOR_HOME" \
         --operator-account "$OPERATOR" --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
         --evidence-dir "$IEV" > "$IEV/probes.log" 2>&1
    then
      emit_finding "$ITER" probes PASS "$TAINT" 'every probe passed for the right reason' "$IEV/probes.log"
    else
      emit_finding "$ITER" probes FAIL "$TAINT" 'one or more probes failed' "$IEV/probes.log"
      TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
      if [ -z "$TAINT" ]; then TAINT='probes'; fi
    fi
  else
    emit_finding "$ITER" probes SKIP "${TAINT:-arm}" 'precondition unmet: the gate never armed' ''
  fi

  # --- step 4+5: teardown and verify-clean --------------------------------
  # No precondition: teardown is attempted no matter what happened above,
  # because leaving state behind is the one thing that poisons every later
  # iteration.
  if "$HERE/teardown-verify.sh" --storage "$STORAGE" --home "$OPERATOR_HOME" \
       --operator-account "$OPERATOR" --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
       --evidence-dir "$IEV" > "$IEV/teardown.log" 2>&1
  then
    emit_finding "$ITER" teardown PASS "$TAINT" 'torn down and verified clean by observed state' "$IEV/teardown.log"
  else
    emit_finding "$ITER" teardown FAIL "$TAINT" 'teardown or verify-clean failed; stopping the night' "$IEV/teardown.log"
    TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
    NIGHT_STOPPED='teardown'
    break
  fi

  if [ -n "$STOP_FIRST" ] && [ "$TOTAL_FAILURES" -gt 0 ]; then
    NIGHT_STOPPED='stop-at-first-divergence'
    break
  fi

  if [ "$MODE" = 'reboot' ]; then
    # Reboot legs need the host to come back and resume, which is a launchd
    # concern rather than a loop concern: the plist re-invokes run-loop.sh on
    # boot with the remaining count. Emitting the marker and returning keeps
    # this script honest about what it did and did not do.
    emit_finding "$ITER" reboot-leg PASS "$TAINT" 'iteration complete; a reboot leg resumes from the launchd job' "$IEV"
  fi

  ITER=$((ITER + 1))
done

printf 'LOOP=END iterations_run=%s failures=%s stopped=%s findings=%s\n' \
  "$((ITER > ITERATIONS ? ITERATIONS : ITER))" "$TOTAL_FAILURES" \
  "${NIGHT_STOPPED:-no}" "$FINDINGS"

if [ -n "$NIGHT_STOPPED" ]; then exit 1; fi
if [ "$TOTAL_FAILURES" -ne 0 ]; then exit 1; fi
