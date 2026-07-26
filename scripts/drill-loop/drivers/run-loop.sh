#!/usr/bin/env bash
#
# run-loop.sh - the autonomous drill loop.
#
# Runs the drill ladder N times unattended and captures everything. There is no
# model in this loop: it is deterministic bash plus expect, so it does not need
# any API credential and nothing about it depends on a login session staying
# alive. Intelligence enters afterwards, reading the artifacts in the morning.
#
#   kickstart daemons -> mint -> preflight -> arm -> probes -> teardown -> verify
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
#     [--evidence-root <dir>] [--build-sha <sha>] \
#     [--stop-at-first-divergence]
#
# --stop-at-first-divergence is an INTERACTIVE debugging flag. It is never used
# by the scheduled run; a nightly loop that stops at the first bug wastes the
# night.
#
# There is no `--passphrase-file`. It was rail-checked here and passed to
# nothing (the TTY confirmation is answered by expect/arm-expect.exp), and the
# wrapper's matching flag was validated root-run surface with no consumer. Both
# are gone rather than better documented; that is round 2's `--endpoint` finding
# under a new name.

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

# ROUND-3 BLOCKER 1. See the long note in run-probe-battery.sh. Both privileged
# wrapper invocations in this file went through a PATH-resolved `sudo`.
PATH="$RAILS_SYSTEM_PATH"
export PATH
SUDO="$(rails_require_cmd sudo)" || die 'sudo is not in a root-owned system directory; refusing to drive a drill night through an unresolvable tool'
GIT="$(rails_require_cmd git)" || die 'git is not in a root-owned system directory'
GREP="$(rails_require_cmd grep)" || die 'grep is not in a root-owned system directory'
SED="$(rails_require_cmd sed)" || die 'sed is not in a root-owned system directory'
DATE="$(rails_require_cmd date)" || die 'date is not in a root-owned system directory'
MKDIR="$(rails_require_cmd mkdir)" || die 'mkdir is not in a root-owned system directory'
MKTEMP="$(rails_require_cmd mktemp)" || die 'mktemp is not in a root-owned system directory'
RM="$(rails_require_cmd rm)" || die 'rm is not in a root-owned system directory'

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
# The subshell is mandatory, not cosmetic: `rails__die` calls `exit`, so a
# DIRECT call would terminate this script before `rail_stop` could print the
# machine-readable LOOP=STOP token. Wrapping it turns the exit into a status
# the `||` can act on, exactly as the command-substitution form does.
# `hostname` and `scutil` go through the absolute resolver because the review
# defeated this rail with a planted `hostname` on PATH.
( rails_assert_host_allowed_observed \
    "$(rails_host_fingerprint_local)" \
    "$(rails__sys hostname -s 2>/dev/null || printf '')" \
    "$(rails__sys hostname -f 2>/dev/null || rails__sys hostname 2>/dev/null || printf '')" \
    "$(rails__sys scutil --get ComputerName 2>/dev/null || printf '')" \
    "$(rails__sys scutil --get LocalHostName 2>/dev/null || printf '')" ) \
  || rail_stop "host rail refused $(rails__sys hostname -s 2>/dev/null || printf 'unknown')"

OPERATOR_UID="$(rails_assert_non_root_account operator "$OPERATOR")" \
  || rail_stop "operator account rejected: $OPERATOR"
[ -n "$OPERATOR_UID" ] || rail_stop 'empty operator uid after rail'
AGENT_UID="$(rails_assert_account_uid agent "$AGENT" "$AGENT_UID_IN")" \
  || rail_stop "agent account rejected: $AGENT"
[ -n "$AGENT_UID" ] || rail_stop 'empty agent uid after rail'

# The AGENT PRINCIPAL, against the compiled-in allowlist. The root wrapper runs
# this rail too and its verdict is the one that matters; running it here as well
# means the loop stops at its own layer with a legible reason instead of every
# verb refusing one at a time.
( rails_assert_agent_account_allowed "$AGENT" ) \
  || rail_stop "agent account is not on the compiled-in drill agent allowlist: $AGENT"

# WRAPPER INTEGRITY. Re-assemble from the repo, then require the repo, the
# committed hash and the INSTALLED file to agree. This is what catches both
# "you edited the repo and forgot to reinstall" and "someone edited the
# installed wrapper", and it runs before the loop can invoke it even once.
ASSEMBLED="$("$MKTEMP" "${TMPDIR:-/tmp}/sanctuary-drill-wrapper-check.XXXXXX")"
cleanup_assembled() { "$RM" -f "$ASSEMBLED"; }
trap cleanup_assembled EXIT
"$ROOT/build-wrapper.sh" --stdout > "$ASSEMBLED" \
  || rail_stop 'could not re-assemble the wrapper from the repo'
( rails_assert_wrapper_integrity "$ASSEMBLED" "$INSTALLED_WRAPPER" "$ROOT/wrapper.sha256" ) \
  || rail_stop 'wrapper integrity rail refused'

# THE GRANT TARGET'S DIRECTORY, not just the file. `rails_assert_wrapper_*`
# checks the wrapper's own ownership and mode and never the chain above it
# (round-3 M3). On an Intel Mac, Homebrew owns `/usr/local`, so an
# operator-writable `/usr/local/sbin` would let the operator replace the exact
# path the NOPASSWD grant names.
( rails_assert_trusted_dir_chain 'grant target dir' "${INSTALLED_WRAPPER%/*}" >/dev/null ) \
  || rail_stop "the directory holding the NOPASSWD grant target is not a trusted root-owned chain: ${INSTALLED_WRAPPER%/*}"

if [ -z "$BUILD_SHA" ]; then
  BUILD_SHA="$("$GIT" -C "$REPO" rev-parse HEAD 2>/dev/null || printf '')"
fi

# LOWERCASE `t`, not `T`. The run id is `<stamp>-<iteration>` and run ids are
# lowercase-only now, because the drill hosts' APFS volume is case-insensitive
# and `...T...` / `...t...` were two accepted ids naming ONE directory entry.
STAMP="$("$DATE" +%Y%m%dt%H%M%S)"
if [ -z "$EVIDENCE_ROOT" ]; then
  EVIDENCE_ROOT="$OPERATOR_HOME/sanctuary-drill-loop-evidence/$STAMP"
fi
"$MKDIR" -p "$EVIDENCE_ROOT"
FINDINGS="$EVIDENCE_ROOT/FINDINGS.jsonl"
: > "$FINDINGS"

# LOOP LOCK. A scheduled run and an interactive drill must never interleave.
LOCK="$OPERATOR_HOME/.sanctuary-drill-loop.lock"
# ROUND-5 L3. The subshell is mandatory here for the same reason it is on every
# other rail call in this file: `rails__die` calls `exit`, so a DIRECT call
# terminates this script at status 20 before `rail_stop` can print the
# machine-readable `LOOP=STOP` token the design promises. A lock rejection
# failed closed and failed SILENTLY, which is the one thing the loop's own
# morning-readability rule forbids.
( rails_lock_acquire "$LOCK" 60 ) || rail_stop "could not acquire the loop lock at $LOCK"
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
  printf '%s' "$1" | "$SED" -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/	/\\t/g'
}

# The battery's own account of what it ran, verbatim, so this loop can never
# summarize it as more than it was. The reviewed loop wrote 'every probe passed
# for the right reason' on a zero exit, while the battery documented eight
# probes and implemented six.
probe_summary() {
  local line
  line="$("$GREP" -m1 '^PROBE=SUMMARY' "$1" 2>/dev/null || printf '')"
  if [ -n "$line" ]; then printf '%s' "$line"; else printf 'the probe battery produced no SUMMARY line'; fi
}

# THE KICKSTART VERB'S OWN ACCOUNT OF WHAT IT DID, verbatim, for the same
# reason `probe_summary` exists: this loop must never describe a step as more
# than the step said it was. The wrapper answers in four fields (restarted,
# absent_expected, absent_unexpected, restart_failed) plus the OBSERVED arm
# state that decided which absences were expected; all of it goes into the
# finding so the three outcomes are distinguishable in the morning.
#
# On the refusal path there is no `WRAPPER=OK` line -- the verb died -- so the
# REJECT reason carries the same breakdown and is read instead. Pure shell, no
# external command: a `grep`/`tail` here would be the round-3 BLOCKER-1 shape.
kickstart_summary() {
  local log="$1" ok='' reject='' line
  [ -f "$log" ] || { printf ''; return 0; }
  while IFS= read -r line; do
    case "$line" in
      'WRAPPER=OK verb=kickstart-daemons '*) ok="${line#WRAPPER=OK verb=kickstart-daemons }" ;;
      'WRAPPER=REJECT reason=kickstart failed for:'*) reject="${line#WRAPPER=REJECT reason=}" ;;
    esac
  done < "$log"
  if [ -n "$ok" ]; then printf '%s' "$ok"; else printf '%s' "$reject"; fi
}

# PREFLIGHT'S OWN ACCOUNT, for the same reason as the kickstart one above.
#
# This step used to record the fixed sentence `all preflight checks passed`,
# which is now a claim preflight does not make: as of the 2026-07-25 follow-on it
# reports THREE verdicts, and a run with `expected=2 failures=0` is a clean
# pre-arm host whose per-uid gate daemons legitimately are not up yet. Writing
# "all checks passed" over that hides the third state from exactly the file a
# morning reader greps -- the same shape as `(restarted: none)` standing in for
# three different mornings.
#
# The summary is preflight's LAST line by construction, and it is the only line
# a driver reads: every check's own verdict is in the log artifact, which the
# finding already points at.
preflight_summary() {
  local log="$1" summary='' line
  [ -f "$log" ] || { printf ''; return 0; }
  while IFS= read -r line; do
    case "$line" in
      'PREFLIGHT=SUMMARY '*) summary="${line#PREFLIGHT=SUMMARY }" ;;
    esac
  done < "$log"
  printf '%s' "$summary"
}

# THE RESULT OF A PROBE RUN. The fold itself lives in lib/rails.sh as
# `rails_probe_result`, a pure function driven exhaustively by both batteries;
# see the long note there for why a skipped probe can never become a PASS.
probe_result() {
  local out
  out="$(rails_probe_result "$1" "$2")" || rail_stop "probe-result rail rejected: rc=$1"
  if [ -z "$out" ]; then rail_stop 'empty result after the probe-result rail'; fi
  printf '%s' "$out"
}

emit_finding() {
  # emit_finding <iteration> <step> <result> <taint> <detail> <artifacts>
  printf '{"iteration":%s,"step":"%s","result":"%s","tainted_by":"%s","detail":"%s","artifacts":"%s","build_sha":"%s","ts":"%s"}\n' \
    "$1" "$(json_escape "$2")" "$(json_escape "$3")" "$(json_escape "$4")" \
    "$(json_escape "$5")" "$(json_escape "$6")" "$(json_escape "${BUILD_SHA:-unknown}")" \
    "$("$DATE" -u +%Y-%m-%dT%H:%M:%SZ)" >> "$FINDINGS"
}

retire_iteration() {
  # retire_iteration <iteration> <run-id> <evidence-dir> <taint> <reason>
  local iter="$1" run_id="$2" iev="$3" taint="$4" reason="$5" log rc=0
  log="$iev/retire-$reason.log"
  if "$SUDO" -n "$INSTALLED_WRAPPER" retire \
       --run-id "$run_id" --operator-account "$OPERATOR" > "$log" 2>&1
  then
    emit_finding "$iter" retire PASS "$taint" "retired disposable fortress after $reason" "$log"
    return 0
  else
    rc=$?
  fi
  emit_finding "$iter" retire FAIL "$taint" "could not retire disposable fortress after $reason (rc=$rc); host may be dirty" "$log"
  return "$rc"
}

ITER=1
NIGHT_STOPPED=''
TOTAL_FAILURES=0

while [ "$ITER" -le "$ITERATIONS" ]; do
  IEV="$EVIDENCE_ROOT/iteration-$ITER"
  "$MKDIR" -p "$IEV"
  printf 'LOOP=ITERATION n=%s evidence=%s\n' "$ITER" "$IEV"

  # A fresh disposable fortress per iteration. The loop supplies a RUN ID,
  # never a path: the ROOT wrapper composes the path itself under a root-owned
  # base it compiled in, and creates it. This driver derives the same string
  # locally only so it can READ the result, and re-asserts it through the rail
  # before doing so.
  RUN_ID="$STAMP-$ITER"
  ( rails_assert_run_id "$RUN_ID" >/dev/null ) || rail_stop "run id rejected: $RUN_ID"

  # Preconditions, tracked so a failed step only skips what genuinely depends
  # on it. `armed` gates the through-gate probes; nothing gates teardown.
  ARMED=''
  TAINT=''

  # --- step 0: the daemons must be on the dist under test -----------------
  # D7 was "the gate daemon was serving a stale dist". The wrapper has had a
  # `kickstart-daemons` verb since the first build and NO driver called it, so
  # the spec's "daemon freshly kickstarted on the current dist" was not wired
  # up anywhere. It is now, and preflight independently checks the result.
  #
  # ROUND-3 H3: the labels this verb restarted were
  # `com.sanctuary.egress-gate{,-peer-resolver}` and the product's are
  # `ai.sanctuaryprotocol.egress-gate{,-peer-resolver}.<agent uid>`. Wrong
  # prefix AND no uid suffix, and this call site passed no `--agent-uid` at all,
  # so the labels could not have been fixed from here even with the right
  # prefix. A failed kickstart is (correctly) fatal to the iteration, so the
  # loop as shipped could not complete a single iteration on any host.
  #
  # 2026-07-25, the first LIVE run: it still could not, because the verb read
  # the per-uid gate daemons' expected pre-arm ABSENCE as a failed restart. The
  # wrapper now answers in four fields and this finding carries them verbatim,
  # so a morning reader can tell "restarted", "absent and expected" and "failed"
  # apart. `(restarted: none)` told them none of the three.
  KICK_RC=0
  "$SUDO" -n "$INSTALLED_WRAPPER" kickstart-daemons \
       --run-id "$RUN_ID" --operator-account "$OPERATOR" \
       --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
       > "$IEV/kickstart.log" 2>&1 || KICK_RC=$?
  KICK_SUMMARY="$(kickstart_summary "$IEV/kickstart.log")"
  if [ "$KICK_RC" -eq 0 ] && [ -n "$KICK_SUMMARY" ]; then
    emit_finding "$ITER" kickstart PASS '' "every daemon that exists is on the dist under test: $KICK_SUMMARY" "$IEV/kickstart.log"
  else
    if [ "$KICK_RC" -eq 0 ]; then
      # Exited 0 without its own verdict line. The same shape as an OK dump
      # that observed nothing: it must not be read as a successful restart.
      kick_detail='kickstart exited 0 without its verdict line; what it restarted cannot be trusted'
    else
      kick_detail="a daemon that EXISTS did not restart, or one that should exist by now is absent; the iteration would measure stale or absent code${KICK_SUMMARY:+ ($KICK_SUMMARY)}"
    fi
    emit_finding "$ITER" kickstart FAIL '' "$kick_detail" "$IEV/kickstart.log"
    TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
    TAINT='kickstart'
    if ! retire_iteration "$ITER" "$RUN_ID" "$IEV" "$TAINT" 'kickstart-failure'; then
      TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
      NIGHT_STOPPED='retire-after-kickstart'
      break
    fi
    if [ -n "$STOP_FIRST" ]; then NIGHT_STOPPED='kickstart'; break; fi
    ITER=$((ITER + 1))
    continue
  fi

  # --- step 0b: mint the disposable fortress, as root, root-owned ---------
  if ! "$SUDO" -n "$INSTALLED_WRAPPER" mint \
       --run-id "$RUN_ID" --operator-account "$OPERATOR" > "$IEV/mint.log" 2>&1
  then
    emit_finding "$ITER" mint FAIL "$TAINT" 'the wrapper could not mint the disposable fortress' "$IEV/mint.log"
    TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
    if [ -z "$TAINT" ]; then TAINT='mint'; fi
    if ! retire_iteration "$ITER" "$RUN_ID" "$IEV" "$TAINT" 'mint-failure'; then
      TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
      NIGHT_STOPPED='retire-after-mint'
      break
    fi
    if [ -n "$STOP_FIRST" ]; then NIGHT_STOPPED='mint'; break; fi
    ITER=$((ITER + 1))
    continue
  fi

  DERIVED="$(rails_derive_disposable_storage "$RAILS_DISPOSABLE_BASE" "$OPERATOR" "$RUN_ID")" \
    || rail_stop "run id rejected: $RUN_ID"
  [ -n "$DERIVED" ] || rail_stop 'empty derived storage path'
  ANCHOR="$(rails_assert_trusted_dir_chain 'operator anchor' "$RAILS_DISPOSABLE_BASE/$OPERATOR")" \
    || rail_stop 'operator anchor is not a trusted root-owned chain'
  STORAGE="$(rails_assert_disposable_storage "$ANCHOR" "$DERIVED")" \
    || rail_stop "storage rail rejected the derived path: $DERIVED"
  [ -n "$STORAGE" ] || rail_stop 'empty storage after rail'

  # --- step 1: preflight ---------------------------------------------------
  PREFLIGHT_RC=0
  "$HERE/preflight.sh" --run-id "$RUN_ID" --operator-account "$OPERATOR" \
       --build-sha "$BUILD_SHA" --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
       > "$IEV/preflight.log" 2>&1 || PREFLIGHT_RC=$?
  PREFLIGHT_SUMMARY="$(preflight_summary "$IEV/preflight.log")"
  if [ "$PREFLIGHT_RC" -eq 0 ] && [ -n "$PREFLIGHT_SUMMARY" ]; then
    emit_finding "$ITER" preflight PASS '' "no preflight check failed: $PREFLIGHT_SUMMARY" "$IEV/preflight.log"
  else
    # A zero exit with NO summary line is the same shape as an OK dump that
    # observed nothing: preflight exits 0 only after printing its own account,
    # so a missing one means it died partway and every check after that point
    # was never made. That is a failure, not a pass with a thin detail.
    if [ "$PREFLIGHT_RC" -eq 0 ]; then
      emit_finding "$ITER" preflight FAIL '' 'preflight exited 0 without printing its own summary; it did not run to the end' "$IEV/preflight.log"
    else
      emit_finding "$ITER" preflight FAIL '' "one or more preflight checks failed: ${PREFLIGHT_SUMMARY:-<no summary printed>}" "$IEV/preflight.log"
    fi
    TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
    TAINT='preflight'
    # A preflight failure is a finding, not a crash. The iteration aborts
    # cleanly rather than measuring a host we already know is wrong, but the
    # loop keeps going.
    if ! retire_iteration "$ITER" "$RUN_ID" "$IEV" "$TAINT" 'preflight-failure'; then
      TOTAL_FAILURES=$((TOTAL_FAILURES + 1))
      NIGHT_STOPPED='retire-after-preflight'
      break
    fi
    if [ -n "$STOP_FIRST" ]; then NIGHT_STOPPED='preflight'; break; fi
    ITER=$((ITER + 1))
    continue
  fi

  # --- step 2: provision + arm --------------------------------------------
  if "$ROOT/expect/arm-expect.exp" \
       "$INSTALLED_WRAPPER" "$RUN_ID" "$OPERATOR" "$AGENT" "$AGENT_UID" \
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
    PROBE_RC=0
    "$HERE/run-probe-battery.sh" --run-id "$RUN_ID" \
      --operator-account "$OPERATOR" --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
      --evidence-dir "$IEV" > "$IEV/probes.log" 2>&1 || PROBE_RC=$?
    PROBE_SUMMARY="$(probe_summary "$IEV/probes.log")"
    PROBE_RESULT="$(probe_result "$PROBE_RC" "$PROBE_SUMMARY")"
    emit_finding "$ITER" probes "$PROBE_RESULT" "$TAINT" "$PROBE_SUMMARY" "$IEV/probes.log"
    if [ "$PROBE_RESULT" != 'PASS' ]; then
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
  if "$HERE/teardown-verify.sh" --run-id "$RUN_ID" \
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
