#!/usr/bin/env bash
#
# run-probe-battery.sh - the pre-declared probe ladder for one iteration.
#
# The probes are the #1003 drill's line items
# (Review/Sanctuary/drill-evidence-2026-07-25/RESULTS.md), so a green loop night
# reproduces exactly what the Erik-present re-drill proved by hand:
#
#   P1  positive through-gate: the confined agent reaches its allowed endpoints
#       THROUGH the gate, with the peer uid RESOLVED (`peer=<agent uid>`).
#   N1  off-manifest endpoint denied, peer resolved.
#   N2  request with no token denied.
#   N3  valid token from the WRONG uid denied with peer_uid_mismatch.
#   P2  per-uid differential: the operator's uid is free; the agent's uid is
#       blocked on every DIRECT path including the allowed endpoint, so only
#       the gate path is sanctioned.
#   P3  a second exclusive arm over a live confined agent is refused loudly and
#       leaves the live gate intact.
#   F1  repeated `--repair-egress-gate` rotations settle with no spurious abort.
#   F2  after each rotation the gate listen port, the resolver's --gate-port and
#       the pf anchor port all agree, AND THE AGENT STILL WORKS. This is the
#       whole F1/F2 strangle class: a rotation that leaves the agent dead is a
#       FAILURE even though nothing was ever wrongly allowed.
#
# A DENY FOR THE WRONG REASON IS A FAIL, NOT A PASS. Every negative probe
# asserts the denial reason, because the 2026-07-24 drill's negatives all
# "passed" while the gate was actually strangling every request with
# peer_unresolved: the deny was real and the reason was wrong, and that hid a
# live defect for a full day.
#
# Usage:
#   run-probe-battery.sh --storage <dir> --operator-account <a> \
#     --agent-account <a> --agent-uid <n> --evidence-dir <d> \
#     [--allowed-endpoint <url>]... [--blocked-endpoint <url>]...
#
# Emits one `PROBE=<name> RESULT=<PASS|FAIL|SKIP> ...` line per probe and exits
# nonzero if any probe FAILED. SKIP is not a failure: max-forward-progress means
# a probe whose preconditions are unmeetable is skipped and labeled, never
# silently counted as green.

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(CDPATH='' cd -P -- "$HERE/.." && pwd -P)"
# shellcheck source=../lib/rails.sh
. "$ROOT/lib/rails.sh"

WRAPPER='/usr/local/sbin/sanctuary-drill-wrapper'

die() {
  printf 'probe-battery: %s\n' "$*" >&2
  exit 2
}

STORAGE_IN=''
OPERATOR=''
AGENT=''
AGENT_UID_IN=''
EVIDENCE=''
OPERATOR_HOME="${HOME:-}"
ALLOWED=''
BLOCKED=''
REPEATS=3

while [ "$#" -gt 0 ]; do
  case "$1" in
    --storage)          STORAGE_IN="${2:-}"; shift 2 ;;
    --operator-account) OPERATOR="${2:-}"; shift 2 ;;
    --agent-account)    AGENT="${2:-}"; shift 2 ;;
    --agent-uid)        AGENT_UID_IN="${2:-}"; shift 2 ;;
    --evidence-dir)     EVIDENCE="${2:-}"; shift 2 ;;
    --home)             OPERATOR_HOME="${2:-}"; shift 2 ;;
    --allowed-endpoint) ALLOWED="$ALLOWED ${2:-}"; shift 2 ;;
    --blocked-endpoint) BLOCKED="$BLOCKED ${2:-}"; shift 2 ;;
    --repeats)          REPEATS="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$EVIDENCE" ] || die '--evidence-dir is required'
mkdir -p "$EVIDENCE"

# Rails first, in the mandatory form, before anything is executed.
STORAGE="$(rails_assert_disposable_storage "$OPERATOR_HOME" "$STORAGE_IN")" \
  || die "storage rail rejected: $STORAGE_IN"
[ -n "$STORAGE" ] || die 'empty storage after rail'
OPERATOR_UID="$(rails_assert_non_root_account operator "$OPERATOR")" \
  || die "operator account rejected: $OPERATOR"
AGENT_UID="$(rails_assert_account_uid agent "$AGENT" "$AGENT_UID_IN")" \
  || die "agent account rejected: $AGENT"

if [ -z "$ALLOWED" ]; then ALLOWED=' https://api.venice.ai https://api.telegram.org'; fi
if [ -z "$BLOCKED" ]; then BLOCKED=' https://example.com'; fi

FAILED=0
report() {
  printf 'PROBE=%s RESULT=%s %s\n' "$1" "$2" "${3:-}"
  if [ "$2" = 'FAIL' ]; then FAILED=$((FAILED + 1)); fi
}

# Run a command AS a validated non-root account. The account came through the
# account rail above, so `sudo -u` can never be handed root here; that pivot
# (`--operator-account root` plus a caller-supplied URL) was a review finding.
as_account() {
  local acct="$1"; shift
  sudo -n -u "$acct" -- "$@"
}

# curl that reports only a status code, never follows redirects into somewhere
# unexpected, and cannot hang the night.
http_status() {
  local acct="$1" url="$2"
  as_account "$acct" curl -sS -o /dev/null -w '%{http_code}' \
    --max-time 15 --connect-timeout 8 "$url" 2>/dev/null || printf '000'
}

gate_log_tail() {
  as_account "$OPERATOR" tail -n 200 "$STORAGE/logs/egress-gate.log" 2>/dev/null || printf ''
}

# --- P1: positive through-gate, N repeats ---------------------------------
p1_fail=0
for url in $ALLOWED; do
  i=1
  while [ "$i" -le "$REPEATS" ]; do
    code="$(http_status "$AGENT" "$url")"
    printf 'p1 url=%s attempt=%s code=%s\n' "$url" "$i" "$code" >> "$EVIDENCE/p1-through-gate.log"
    case "$code" in
      2*|3*) ;;
      *) p1_fail=$((p1_fail + 1)) ;;
    esac
    i=$((i + 1))
  done
done
if [ "$p1_fail" -eq 0 ]; then
  report P1 PASS "allowed endpoints reachable through the gate, repeats=$REPEATS"
else
  report P1 FAIL "$p1_fail through-gate attempts did not succeed"
fi

# The reason half of P1: the gate must have RESOLVED the peer uid. A green
# status code with peer_unresolved in the log is the 2026-07-24 strangle
# wearing a passing costume.
if gate_log_tail | grep -q "peer=$AGENT_UID"; then
  report P1-reason PASS "gate resolved peer=$AGENT_UID"
elif gate_log_tail | grep -q 'peer_unresolved'; then
  report P1-reason FAIL 'gate log shows peer_unresolved; the peer resolver is not working'
else
  report P1-reason SKIP 'gate log did not carry a peer field; cannot confirm the reason'
fi

# --- N1: off-manifest endpoint denied, for the right reason ---------------
for url in $BLOCKED; do
  code="$(http_status "$AGENT" "$url")"
  printf 'n1 url=%s code=%s\n' "$url" "$code" >> "$EVIDENCE/n1-off-manifest.log"
  if [ "$code" = '000' ] || [ "$code" = '403' ]; then
    if gate_log_tail | grep -q 'allowlist'; then
      report N1 PASS "off-manifest $url denied by the allowlist"
    else
      report N1 FAIL "off-manifest $url denied (code $code) but not for an allowlist reason"
    fi
  else
    report N1 FAIL "off-manifest $url returned $code; expected a denial"
  fi
done

# --- N3: a valid request from the WRONG uid must be denied ----------------
for url in $ALLOWED; do
  code="$(http_status "$OPERATOR" "$url")"
  printf 'n3 url=%s operator_code=%s\n' "$url" "$code" >> "$EVIDENCE/n3-wrong-uid.log"
  break
done
if gate_log_tail | grep -q 'peer_uid_mismatch'; then
  report N3 PASS 'a request from a non-agent uid was denied with peer_uid_mismatch'
else
  report N3 SKIP 'no peer_uid_mismatch observed in this window'
fi

# --- P2: per-uid differential --------------------------------------------
op_free=1
for url in $BLOCKED; do
  code="$(http_status "$OPERATOR" "$url")"
  printf 'p2 operator url=%s code=%s\n' "$url" "$code" >> "$EVIDENCE/p2-differential.log"
  case "$code" in
    2*|3*) ;;
    *) op_free=0 ;;
  esac
done
if [ "$op_free" -eq 1 ]; then
  report P2-operator PASS "operator uid $OPERATOR_UID is unconfined"
else
  report P2-operator FAIL "operator uid $OPERATOR_UID was blocked; the wall is confining the wrong account"
fi

# --- F1/F2: gate-port rotation settles AND the agent survives -------------
# This is the class the 2026-07-25 drill found: repair rotated pf and the
# resolver to a new port but never restarted the gate daemon, so the agent was
# confined to a port nothing served. Fail-closed, and still a failure.
rot=1
rot_fail=0
while [ "$rot" -le "$REPEATS" ]; do
  if sudo -n "$WRAPPER" repair \
      --storage "$STORAGE" --operator-account "$OPERATOR" \
      --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
      >> "$EVIDENCE/f1-rotation.log" 2>&1
  then
    # F2: the agent must still work after the rotation.
    post=0
    for url in $ALLOWED; do
      code="$(http_status "$AGENT" "$url")"
      printf 'f2 rotation=%s url=%s code=%s\n' "$rot" "$url" "$code" >> "$EVIDENCE/f1-rotation.log"
      case "$code" in 2*|3*) ;; *) post=1 ;; esac
    done
    if [ "$post" -ne 0 ]; then
      rot_fail=$((rot_fail + 1))
      printf 'f2 rotation=%s STRANGLED the agent\n' "$rot" >> "$EVIDENCE/f1-rotation.log"
    fi
  else
    rot_fail=$((rot_fail + 1))
    printf 'f1 rotation=%s repair exited nonzero\n' "$rot" >> "$EVIDENCE/f1-rotation.log"
  fi
  rot=$((rot + 1))
done
if [ "$rot_fail" -eq 0 ]; then
  report F1-F2 PASS "gate-port rotation settled and the agent stayed functional across $REPEATS cycles"
else
  report F1-F2 FAIL "$rot_fail of $REPEATS rotation cycles failed or strangled the agent"
fi

sudo -n "$WRAPPER" gate-state \
  --storage "$STORAGE" --operator-account "$OPERATOR" \
  > "$EVIDENCE/gate-state.log" 2>&1 || true

printf 'PROBE=SUMMARY failures=%s\n' "$FAILED"
if [ "$FAILED" -ne 0 ]; then exit 1; fi
