#!/usr/bin/env bash
#
# run-probe-battery.sh - the pre-declared probe ladder for one iteration.
#
# The probes are the #1003 drill's line items
# (Review/Sanctuary/drill-evidence-2026-07-25/RESULTS.md), so a green loop night
# reproduces what the Erik-present re-drill proved by hand:
#
#   P1  positive through-gate: the confined agent reaches its allowed endpoints
#       THROUGH the gate, with the peer uid RESOLVED (`peer=<agent uid>`).
#   N1  off-manifest endpoint denied, peer resolved.
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
# WHAT THIS BATTERY DOES NOT REPRODUCE, said here rather than implied by
# silence. The 2026-07-25 re-review found the header of this file declaring an
# `N2` ("request with no token denied") that had no code, while a green run
# printed "every probe passed for the right reason". N2 belongs to the gate's
# TCB / fail-closed client-auth mode; the drill this battery reproduces runs the
# ADVISORY peer mode, where an ordinary curl carries no proxy-authorization
# header at all and N2 is not a meaningful question. It is therefore not
# implemented and not claimed. If the loop is ever pointed at a clientAuth
# configuration, N2 goes in as a real probe, not as a comment.
#
# A DENY FOR THE WRONG REASON IS A FAIL, NOT A PASS. Every negative probe
# asserts the denial reason, because the 2026-07-24 drill's negatives all
# "passed" while the gate was actually strangling every request with
# peer_unresolved: the deny was real and the reason was wrong, and that hid a
# live defect for a full day.
#
# THE SAME RULE APPLIED TO THE BATTERY ITSELF. A probe that could not RUN is
# reported SKIP with the reason, never PASS, and the summary line names which
# probes ran and which did not.
#
# AND A SKIPPED BATTERY IS NOT A GREEN BATTERY. Round 3 (Codex finding 2) found
# that saying so was not enough: a skipped `N3` left `FAILED` at zero, this file
# exited 0, and `run-loop.sh` recorded the whole probe step as `"result":"PASS"`.
# A declared negative probe that never observed the reason it exists to prove,
# summarized as a pass, IS the 2026-07-24 false-green class. So SKIP is now
# counted, the summary carries an explicit `verified=yes|no`, and this file
# exits 3 (UNVERIFIED) when anything was skipped. There is no arrangement of
# outputs in which a skip can be read as a pass.
#
# Usage:
#   run-probe-battery.sh --run-id <id> --operator-account <a> \
#     --agent-account <a> --agent-uid <n> --evidence-dir <d> \
#     [--allowed-endpoint <url>]... [--blocked-endpoint <url>]... [--base <dir>]
#
# Emits one `PROBE=<name> RESULT=<PASS|FAIL|SKIP> ...` line per probe.
# Exit: 0 every declared probe RAN and passed; 1 a probe FAILED;
#       2 usage or a precondition; 3 UNVERIFIED (a declared probe was skipped).

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

# ---------------------------------------------------------------------------
# ROUND-3 BLOCKER 1: THE EVIDENCE PATH GETS THE PRIVILEGE PATH'S TREATMENT
# ---------------------------------------------------------------------------
#
# Round 2 closed the PATH class in the root wrapper and left it wide open here.
# Under the stated threat model the attacker controls the environment at this
# unprivileged call site, and this file's entire output is observations. Codex
# planted a `sudo` earlier in PATH and got:
#
#   PROBE=P1 RESULT=PASS ... PROBE=N3 RESULT=PASS ...
#   PROBE=SUMMARY failures=0 ran=P1,P1-reason,N1,N3,P2-operator,P3,F1-F2 skipped=
#
# with no real sudo, no installed wrapper, no pfctl and no agent account. Full
# green evidence for a drill that never happened.
#
# So: PATH is pinned from the rails' single source of truth as a belt, and every
# tool the evidence rests on is resolved ONCE, absolutely, through
# `rails_require_cmd`, which refuses anything outside a root-owned system
# directory rather than falling back to PATH. Nothing below invokes a bare
# command name.
PATH="$RAILS_SYSTEM_PATH"
export PATH
SUDO="$(rails_require_cmd sudo)" || die 'sudo is not in a root-owned system directory; refusing to gather evidence through an unresolvable tool'
CURL="$(rails_require_cmd curl)" || die 'curl is not in a root-owned system directory'
GREP="$(rails_require_cmd grep)" || die 'grep is not in a root-owned system directory'
TRUE_BIN="$(rails_require_cmd true)" || die 'true is not in a root-owned system directory'
MKDIR="$(rails_require_cmd mkdir)" || die 'mkdir is not in a root-owned system directory'
TR="$(rails_require_cmd tr)" || die 'tr is not in a root-owned system directory'

RUN_ID=''
OPERATOR=''
AGENT=''
AGENT_UID_IN=''
EVIDENCE=''
ALLOWED=''
BLOCKED=''
REPEATS=3
# See the note in preflight.sh: unprivileged driver, root wrapper takes no base.
BASE="$RAILS_DISPOSABLE_BASE"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id)           RUN_ID="${2:-}"; shift 2 ;;
    --operator-account) OPERATOR="${2:-}"; shift 2 ;;
    --agent-account)    AGENT="${2:-}"; shift 2 ;;
    --agent-uid)        AGENT_UID_IN="${2:-}"; shift 2 ;;
    --evidence-dir)     EVIDENCE="${2:-}"; shift 2 ;;
    --allowed-endpoint) ALLOWED="$ALLOWED ${2:-}"; shift 2 ;;
    --blocked-endpoint) BLOCKED="$BLOCKED ${2:-}"; shift 2 ;;
    --repeats)          REPEATS="${2:-}"; shift 2 ;;
    --base)             BASE="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$EVIDENCE" ] || die '--evidence-dir is required'
[ -n "$RUN_ID" ] || die '--run-id is required'
"$MKDIR" -p "$EVIDENCE"

# Rails first, in the mandatory form, before anything is executed.
OPERATOR_UID="$(rails_assert_non_root_account operator "$OPERATOR")" \
  || die "operator account rejected: $OPERATOR"
AGENT_UID="$(rails_assert_account_uid agent "$AGENT" "$AGENT_UID_IN")" \
  || die "agent account rejected: $AGENT"
DERIVED="$(rails_derive_disposable_storage "$BASE" "$OPERATOR" "$RUN_ID")" \
  || die "run id rejected: $RUN_ID"
[ -n "$DERIVED" ] || die 'empty derived storage path'
ANCHOR="$(rails_assert_trusted_dir_chain 'operator anchor' "$BASE/$OPERATOR")" \
  || die "operator anchor is not a trusted chain: $BASE/$OPERATOR"
STORAGE="$(rails_assert_disposable_storage "$ANCHOR" "$DERIVED")" \
  || die "storage rail rejected: $DERIVED"
[ -n "$STORAGE" ] || die 'empty storage after rail'

# Endpoint screening. The wrapper screens its own --endpoint argument; these
# never reach the wrapper, but they DO reach curl, so they are screened here to
# the same bar rather than word-split straight onto a command line.
screen_endpoint() {
  case "$1" in
    https://*) ;;
    *) die "endpoint must be an https URL: $1" ;;
  esac
  case "$1" in
    *[!A-Za-z0-9:/._~%?=-]*) die "endpoint has disallowed characters: $1" ;;
  esac
}

if [ -z "$ALLOWED" ]; then ALLOWED=' https://api.venice.ai https://api.telegram.org'; fi
if [ -z "$BLOCKED" ]; then BLOCKED=' https://example.com'; fi
for url in $ALLOWED $BLOCKED; do screen_endpoint "$url"; done

# THE DECLARED LADDER. Named here, once, so the summary can report the exact
# set that was declared against the exact set that ran. A probe that is not in
# this list cannot be reported, and one that is in it and never reported is a
# hole the summary names rather than hides.
DECLARED_PROBES='P1 P1-reason N1 N3 P2-operator P3 F1-F2'

FAILED=0
SKIPPED_COUNT=0
RAN=''
SKIPPED=''
report() {
  printf 'PROBE=%s RESULT=%s %s\n' "$1" "$2" "${3:-}"
  case "$2" in
    FAIL) FAILED=$((FAILED + 1)); RAN="$RAN,$1" ;;
    PASS) RAN="$RAN,$1" ;;
    SKIP) SKIPPED_COUNT=$((SKIPPED_COUNT + 1)); SKIPPED="$SKIPPED,$1" ;;
    *)    die "report: unknown result '$2' for probe $1" ;;
  esac
}

# The ONE place this file decides what its own run was worth. `verified=no`
# whenever anything was skipped, and the exit status agrees with the token, so a
# caller cannot pick the convenient one of the two.
emit_summary() {
  local verified='yes'
  if [ "$SKIPPED_COUNT" -ne 0 ]; then verified='no'; fi
  printf 'PROBE=SUMMARY failures=%s skipped_count=%s verified=%s declared=%s ran=%s skipped=%s\n' \
    "$FAILED" "$SKIPPED_COUNT" "$verified" \
    "$(printf '%s' "$DECLARED_PROBES" | "$TR" ' ' ',')" \
    "${RAN#,}" "${SKIPPED#,}"
}

# Run a command AS a validated non-root account. The account came through the
# account rail above, so `sudo -u` can never be handed root here; that pivot
# (`--operator-account root` plus a caller-supplied URL) was a review finding.
# `$SUDO` is the ABSOLUTE path resolved at the top of this file; a planted
# `sudo` on PATH cannot answer for it.
as_account() {
  local acct="$1"; shift
  "$SUDO" -n -u "$acct" -- "$@"
}

# PRECONDITION. Every probe below observes the world through `sudo -n -u`, and
# the reviewed NOPASSWD grant does not cover it (see sudoers.d/sanctuary-drill,
# which records why widening the grant is not an acceptable resolution). Without
# it every probe would return 000, N1 and P2 would fail for a reason that has
# nothing to do with the gate, and the night would be spent diagnosing the
# harness. So ask once, up front, and say so loudly.
if ! as_account "$OPERATOR" "$TRUE_BIN" >/dev/null 2>&1; then
  for p in $DECLARED_PROBES; do
    report "$p" SKIP "precondition unmet: 'sudo -n -u $OPERATOR' is not permitted on this host"
  done
  emit_summary
  printf 'probe-battery: the as-account grant is missing; NOTHING was measured\n' >&2
  exit 2
fi

# curl that reports only a status code, never follows redirects into somewhere
# unexpected, and cannot hang the night.
http_status() {
  local acct="$1" url="$2"
  as_account "$acct" "$CURL" -sS -o /dev/null -w '%{http_code}' \
    --max-time 15 --connect-timeout 8 "$url" 2>/dev/null || printf '000'
}

# THE REASON HALF'S EVIDENCE SOURCE (round-3 M5).
#
# This used to read `$STORAGE/logs/egress-gate.log`, which nothing writes and
# which an unprivileged process could not read anyway once the product chmods
# the root-owned fortress to 0700. Both failures produced the empty string, so
# `P1-reason` was permanently SKIP, `N3` was permanently SKIP and `N1` failed
# for the wrong reason: the half of the ladder that exists BECAUSE the
# 2026-07-24 drill hid a live `peer_unresolved` strangle behind green-looking
# denials was structurally dead.
#
# It now goes through the wrapper's `gate-log` verb, which reads the paths the
# product actually writes, as root, and exits NONZERO when there is no log to
# read. So "the gate said X" and "I could not see what the gate said" are two
# different answers here, which is the whole point.
GATE_LOG_CACHE="$EVIDENCE/gate-log.txt"
GATE_LOG_RC=0
read_gate_log() {
  GATE_LOG_RC=0
  "$SUDO" -n "$WRAPPER" gate-log \
    --run-id "$RUN_ID" --operator-account "$OPERATOR" \
    --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
    > "$GATE_LOG_CACHE" 2>&1 || GATE_LOG_RC=$?
  return 0
}

# Did the gate log carry <pattern>? Three answers, never two:
#   0  observed, and it matched
#   1  observed, and it did not match
#   2  COULD NOT OBSERVE (no log, or the read failed)
gate_log_says() {
  read_gate_log
  if [ "$GATE_LOG_RC" -ne 0 ]; then return 2; fi
  # -F: these patterns are LITERAL tokens, and a path or uid read as a
  # regular expression could match something adjacent to what was meant.
  if "$GREP" -q -F -- "$1" "$GATE_LOG_CACHE"; then return 0; fi
  return 1
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
#
# THREE outcomes, not two. "the log says the peer resolved" (PASS), "the log
# says peer_unresolved" (FAIL) and "there is no log to read" (SKIP, which now
# makes the whole battery UNVERIFIED) are different facts and are reported as
# different facts.
p1r=0
gate_log_says "peer=$AGENT_UID" || p1r=$?
if [ "$p1r" -eq 2 ]; then
  report P1-reason SKIP "could not READ the gate log (wrapper gate-log rc=$GATE_LOG_RC); the reason half CANNOT be evaluated"
elif [ "$p1r" -eq 0 ]; then
  report P1-reason PASS "gate resolved peer=$AGENT_UID"
else
  p1u=0
  gate_log_says 'peer_unresolved' || p1u=$?
  if [ "$p1u" -eq 0 ]; then
    report P1-reason FAIL 'gate log shows peer_unresolved; the peer resolver is not working'
  else
    report P1-reason FAIL "the gate log was read and carries no peer field for uid $AGENT_UID; the through-gate status codes cannot be attributed to a resolved peer"
  fi
fi

# --- N1: off-manifest endpoint denied, for the right reason ---------------
for url in $BLOCKED; do
  code="$(http_status "$AGENT" "$url")"
  printf 'n1 url=%s code=%s\n' "$url" "$code" >> "$EVIDENCE/n1-off-manifest.log"
  if [ "$code" = '000' ] || [ "$code" = '403' ]; then
    n1r=0
    gate_log_says 'allowlist' || n1r=$?
    if [ "$n1r" -eq 2 ]; then
      report N1 SKIP "off-manifest $url was denied (code $code) but the gate log could not be READ (rc=$GATE_LOG_RC), so the REASON is unmeasured"
    elif [ "$n1r" -eq 0 ]; then
      report N1 PASS "off-manifest $url denied by the allowlist"
    else
      report N1 FAIL "off-manifest $url denied (code $code) but not for an allowlist reason"
    fi
  else
    report N1 FAIL "off-manifest $url returned $code; expected a denial"
  fi
done

# --- N3: a valid request from the WRONG uid must be denied ----------------
#
# Round 3 (Codex finding 2): the absence of `peer_uid_mismatch` used to be SKIP.
# It is not a skip. The probe RAN: a request was made from a non-agent uid and
# the gate log was read. Absence of the denial reason means the reason was not
# observed, which is a FAILURE of the thing the probe exists to prove. SKIP is
# reserved for "the log could not be read at all".
for url in $ALLOWED; do
  code="$(http_status "$OPERATOR" "$url")"
  printf 'n3 url=%s operator_code=%s\n' "$url" "$code" >> "$EVIDENCE/n3-wrong-uid.log"
  break
done
n3r=0
gate_log_says 'peer_uid_mismatch' || n3r=$?
if [ "$n3r" -eq 2 ]; then
  report N3 SKIP "could not READ the gate log (wrapper gate-log rc=$GATE_LOG_RC); the wrong-uid denial reason CANNOT be evaluated"
elif [ "$n3r" -eq 0 ]; then
  report N3 PASS 'a request from a non-agent uid was denied with peer_uid_mismatch'
else
  report N3 FAIL 'the gate log was read and shows no peer_uid_mismatch for the non-agent request; a denial for an unobserved reason is the 2026-07-24 false-green class'
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

# --- P3: a second exclusive arm over a LIVE confined agent ----------------
# Declared in the drill spec, and previously present only as a header comment.
# Two things must both hold: the second arm is REFUSED, and the live gate is
# still intact afterwards. A refusal that kills the running gate is a failure,
# not a pass; that is the same strangle shape as F2.
p3_arm_rc=0
"$SUDO" -n "$WRAPPER" arm \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" \
  --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
  >> "$EVIDENCE/p3-second-arm.log" 2>&1 || p3_arm_rc=$?
printf 'p3 second_arm_rc=%s\n' "$p3_arm_rc" >> "$EVIDENCE/p3-second-arm.log"
if [ "$p3_arm_rc" -eq 0 ]; then
  report P3 FAIL 'a second exclusive arm over a live confined agent SUCCEEDED; it must be refused'
else
  p3_intact=1
  for url in $ALLOWED; do
    code="$(http_status "$AGENT" "$url")"
    printf 'p3 post-refusal url=%s code=%s\n' "$url" "$code" >> "$EVIDENCE/p3-second-arm.log"
    case "$code" in 2*|3*) ;; *) p3_intact=0 ;; esac
  done
  if [ "$p3_intact" -eq 1 ]; then
    report P3 PASS "the second arm was refused (rc=$p3_arm_rc) and the live gate survived it"
  else
    report P3 FAIL "the second arm was refused (rc=$p3_arm_rc) but the live gate did NOT survive it"
  fi
fi

# --- F1/F2: gate-port rotation settles AND the agent survives -------------
# This is the class the 2026-07-25 drill found: repair rotated pf and the
# resolver to a new port but never restarted the gate daemon, so the agent was
# confined to a port nothing served. Fail-closed, and still a failure.
rot=1
rot_fail=0
while [ "$rot" -le "$REPEATS" ]; do
  if "$SUDO" -n "$WRAPPER" repair \
      --run-id "$RUN_ID" --operator-account "$OPERATOR" \
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

"$SUDO" -n "$WRAPPER" gate-state \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" \
  --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
  > "$EVIDENCE/gate-state.log" 2>&1 || true

# A declared probe that never reported at all would otherwise vanish from both
# the ran and the skipped list, so it is counted as unverified here rather than
# silently omitted. This is the same rule the file applies to its probes,
# applied to the file.
for p in $DECLARED_PROBES; do
  case ",$RAN,$SKIPPED," in
    *",$p,"*) ;;
    *) report "$p" SKIP 'declared but never reported; the battery did not reach it' ;;
  esac
done

emit_summary
if [ "$FAILED" -ne 0 ]; then exit 1; fi
# UNVERIFIED. Distinct from both green and failed, and NONZERO, so no caller can
# turn a skipped declared probe into a pass by reading only the exit status.
if [ "$SKIPPED_COUNT" -ne 0 ]; then exit 3; fi
