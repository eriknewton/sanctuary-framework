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
#   N1  off-manifest endpoint denied at the gate, peer resolved.
#   N3  a request from the WRONG uid, made TO THE GATE PORT, is denied with
#       peer_uid_mismatch.
#   P2  per-uid differential: the operator's uid is free on a DIRECT path,
#       so the confinement is per-uid and not host-wide.
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
# ===========================================================================
# ROUND 6: THE OBSERVATION LEDGER, AND WHY THE VERDICT SHAPE CHANGED
# ===========================================================================
#
# Six review rounds found six defects that are ONE defect: EVERY PROBE'S
# VERDICT WAS COMPUTED FROM SOMETHING OTHER THAN THE THING IT CLAIMED TO HAVE
# MEASURED.
#
#   r5 B1  `P1` printed `RESULT=PASS "allowed endpoints reachable through the
#          gate"` for a bare `curl` with no `--proxy`. The gate is a CONNECT
#          proxy on a per-generation loopback port and there is no `rdr`, so
#          that request could not have gone through the gate; the harness had
#          no way to learn the port at all. `N3` was structurally dead for the
#          same reason: `peer_uid_mismatch` is only ever emitted for a socket
#          connected TO the gate port.
#   r5 M1  `--repeats 0` made P1, P2-operator and F1-F2 all print PASS,
#          `verified=yes`, exit 0, having made ZERO requests.
#   r5 M2  `N3`'s status guard read `$code` - an ordinary shell variable last
#          written by the N1 loop. The verdict was bound to a status code from
#          a different probe's request.
#   r5 M3  an ABSENT gate log became a gate-blamed FAIL rather than a
#          could-not-observe.
#
# Fixing those four in place produces a round 7. So the seam moved.
#
# NOTHING IN THIS FILE DECIDES ANYTHING FROM AMBIENT SHELL STATE ANY MORE.
# Every act of looking at the world goes through `measure_*`, which appends an
# OBSERVATION RECORD naming (a) the probe that made it, (b) the mechanism it
# went through, (c) whether it was observed at all, and (d) what came back.
# `report` then takes the observation ids as a REQUIRED argument and refuses to
# emit a PASS or a FAIL that its basis does not support:
#
#   * an empty basis is not a basis            -> zero measurements can never
#                                                 be a PASS; `--repeats 0` is
#                                                 structurally UNOBSERVED.
#   * a basis id from another probe is refused -> M2 is unrepresentable; a
#                                                 verdict cannot borrow another
#                                                 loop's status code.
#   * a record is `observed` or `unobservable` -> "I could not look" is never
#                                                 the same verdict as "I looked
#                                                 and it was denied".
#   * the verdict TEXT is checked against the mechanisms its basis exercised
#     (`rails_assert_claim_supported`)         -> "through the gate" can only
#                                                 be printed by a basis of
#                                                 through-gate requests.
#
# And every emitted line carries the derived, machine-readable `basis=`,
# `channels=` and `observed=` fields, so a reader never has to trust the prose.
#
# A verdict the ledger cannot justify is not silently dropped and not allowed
# through: it is rewritten as `UNOBSERVED`, counted as a HARNESS DEFECT, said
# loudly on stderr, and the battery exits 4. The evidence still gets written -
# suppressing it would be its own kind of lie - but there is no arrangement of
# outputs in which it reads as green.
#
# AND A SKIPPED BATTERY IS NOT A GREEN BATTERY. Round 3 (Codex finding 2) found
# that saying so was not enough: a skipped `N3` left `FAILED` at zero, this file
# exited 0, and `run-loop.sh` recorded the whole probe step as `"result":"PASS"`.
# So SKIP is counted, the summary carries an explicit `verified=yes|no`, and
# this file exits nonzero when anything was skipped.
#
# Usage:
#   run-probe-battery.sh --run-id <id> --operator-account <a> \
#     --agent-account <a> --agent-uid <n> --evidence-dir <d> \
#     [--allowed-endpoint <url>]... [--blocked-endpoint <url>]... \
#     [--repeats <n>] [--base <dir>]
#
# Emits one `PROBE=<name> RESULT=<PASS|FAIL|SKIP|UNOBSERVED> basis=... ...`
# line per probe.
# Exit: 0 every declared probe RAN and passed; 1 a probe FAILED;
#       2 usage or a precondition; 3 UNVERIFIED (a declared probe was skipped
#       or could not be observed); 4 A HARNESS DEFECT (a verdict was attempted
#       that its own observations could not justify).

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
CAT="$(rails_require_cmd cat)" || die 'cat is not in a root-owned system directory'

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

# ROUND-5 M1, the belt half. The ledger is what makes a zero-measurement PASS
# impossible; this makes a zero-measurement RUN impossible to ask for in the
# first place, so the operator gets a usage error instead of an honest but
# useless UNOBSERVED battery. `0` and negatives were accepted before and
# produced a clean, fully green, entirely unmeasured ladder.
case "$REPEATS" in
  ''|*[!0-9]*) die "--repeats must be a positive integer: '$REPEATS'" ;;
esac
[ "$REPEATS" -ge 1 ] || die "--repeats must be at least 1 (got $REPEATS); a battery that measures nothing is not a battery"

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

# ROUND-5 M1, second shape. `--allowed-endpoint ''` left `ALLOWED=" "`, and
# `[ -z "$ALLOWED" ]` is FALSE for a single space, so the default was not
# applied and `for url in $ALLOWED` then iterated zero times. Whitespace-only
# IS empty here; word-splitting is what these variables are for.
normalize_list() {
  local out=''
  # shellcheck disable=SC2048,SC2086
  for _u in $1; do out="$out $_u"; done
  printf '%s' "$out"
}
ALLOWED="$(normalize_list "$ALLOWED")"
BLOCKED="$(normalize_list "$BLOCKED")"
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
DEFECTS=0
RAN=''
SKIPPED=''

# ===========================================================================
# THE OBSERVATION LEDGER
# ===========================================================================
#
# One append-only record per act of looking at the world. `OBS_INDEX` is the
# in-memory half `report` consults; `$EVIDENCE/observations.tsv` is the durable
# half a human reads in the morning. They are written together, by one
# function, so they cannot disagree.
#
# NOTE THE CALLING CONVENTION, AND WHY IT IS NOT A COMMAND SUBSTITUTION.
# `obs_record` sets the GLOBAL `OBS_ID` instead of printing the id. An
# `id="$(obs_record ...)"` would run in a subshell, so the sequence counter and
# the index would be discarded in the parent and every observation would be
# `obs1`. That is the same subshell-swallows-the-effect defect as round 1's
# `die`-inside-`$( )`, arriving through the front door.
OBS_LEDGER="$EVIDENCE/observations.tsv"
: > "$OBS_LEDGER"
printf 'id\tprobe\tkind\tchannel\tstate\toutcome\tsubject\n' >> "$OBS_LEDGER"
OBS_SEQ=0
OBS_INDEX='|'
OBS_ID=''
OBS_CODE=''

# obs_record <probe> <kind> <channel> <state> <outcome> <subject>
#   kind    http | gatelog | wrapper | gateport
#   channel gate | direct | -
#   state   observed | unobservable
obs_record() {
  local probe="$1" kind="$2" channel="$3" state="$4" outcome="$5" subject="$6"
  case "$state" in
    observed|unobservable) ;;
    *) die "obs_record: unknown observation state '$state'" ;;
  esac
  case "$kind" in
    http|gatelog|wrapper|gateport) ;;
    *) die "obs_record: unknown observation kind '$kind'" ;;
  esac
  case "$channel" in
    gate|direct|-) ;;
    *) die "obs_record: unknown observation channel '$channel'" ;;
  esac
  OBS_SEQ=$((OBS_SEQ + 1))
  OBS_ID="obs$OBS_SEQ"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$OBS_ID" "$probe" "$kind" "$channel" "$state" "$outcome" "$subject" >> "$OBS_LEDGER"
  OBS_INDEX="$OBS_INDEX$OBS_ID:$probe:$kind:$channel:$state|"
}

# THE ONE PLACE A VERDICT IS EMITTED, and the one place it can be refused.
#
#   report <probe> <PASS|FAIL|SKIP|UNOBSERVED> <basis-ids> <text>
#
# `basis-ids` is a comma-separated list of ids from THIS probe's observations.
# PASS and FAIL require at least one, and at least one of them must have been
# actually observed. SKIP and UNOBSERVED take `''`: they are statements about
# the harness, not about the world, and they are the only verdicts that may be
# made with nothing in hand.
#
# The claim check runs on PASS and FAIL only, deliberately. A PASS/FAIL line
# asserts something about the wall; an UNOBSERVED line asserts that nothing was
# established, and "could not READ the gate log" must stay sayable. What keeps
# the negative honest is that it cannot be PASS or FAIL, not the wording.
report() {
  local probe="$1" verdict="$2" basis="${3:-}" text="${4:-}"
  local wanted="$2" id rec rest obs_probe obs_kind obs_channel obs_state
  local supported='' observed=0 total=0 bad='' channels='' chanlist='' oldifs reglob=''

  case "$verdict" in
    PASS|FAIL|SKIP|UNOBSERVED) ;;
    *) die "report: unknown result '$verdict' for probe $probe" ;;
  esac

  if [ "$verdict" = 'PASS' ] || [ "$verdict" = 'FAIL' ]; then
    if [ -z "$basis" ]; then
      bad='the verdict named no observation at all'
    else
      oldifs="$IFS"
      case "$-" in *f*) ;; *) reglob='yes' ;; esac
      set -f
      IFS=','
      # shellcheck disable=SC2086
      set -- $basis
      IFS="$oldifs"
      if [ -n "$reglob" ]; then set +f; fi
      for id in "$@"; do
        if [ -z "$id" ]; then continue; fi
        rec=''
        case "$OBS_INDEX" in
          *"|$id:"*) rec="${OBS_INDEX#*"|$id:"}"; rec="${rec%%|*}" ;;
        esac
        if [ -z "$rec" ]; then
          bad="basis $id is not a recorded observation"
          break
        fi
        obs_probe="${rec%%:*}"
        rest="${rec#*:}"
        obs_kind="${rest%%:*}"
        rest="${rest#*:}"
        obs_channel="${rest%%:*}"
        obs_state="${rest#*:}"
        if [ "$obs_probe" != "$probe" ]; then
          bad="basis $id was recorded by probe $obs_probe, not by $probe"
          break
        fi
        total=$((total + 1))
        if [ "$obs_state" = 'observed' ]; then
          observed=$((observed + 1))
          case " $channels " in
            *" $obs_channel "*) ;;
            *) channels="$channels $obs_channel"
               if [ -z "$chanlist" ]; then chanlist="$obs_channel"; else chanlist="$chanlist,$obs_channel"; fi ;;
          esac
          if [ "$obs_kind" = 'http' ] && [ "$obs_channel" = 'gate' ]; then
            supported="$supported gate-channel"
          fi
          if [ "$obs_kind" = 'gatelog' ]; then
            supported="$supported gate-log"
          fi
        fi
      done
      if [ -z "$bad" ] && [ "$observed" -eq 0 ]; then
        bad="all $total observations in the basis were UNOBSERVABLE; nothing was measured"
      fi
      if [ -z "$bad" ]; then
        ( rails_assert_claim_supported "$text" "$supported" ) \
          || bad='the verdict text claims a mechanism no observation in its basis exercised'
      fi
    fi
  fi

  if [ -n "$bad" ]; then
    DEFECTS=$((DEFECTS + 1))
    printf 'probe-battery: *** HARNESS DEFECT *** probe %s attempted %s it cannot justify: %s\n' \
      "$probe" "$wanted" "$bad" >&2
    verdict='UNOBSERVED'
    text="the harness attempted $wanted and could not justify it ($bad); original text: $text"
  fi

  printf 'PROBE=%s RESULT=%s basis=%s observed=%s channels=%s %s\n' \
    "$probe" "$verdict" "${basis:--}" "$observed" "${chanlist:--}" "$text"

  case "$verdict" in
    FAIL) FAILED=$((FAILED + 1)); RAN="$RAN,$probe" ;;
    PASS) RAN="$RAN,$probe" ;;
    SKIP|UNOBSERVED) SKIPPED_COUNT=$((SKIPPED_COUNT + 1)); SKIPPED="$SKIPPED,$probe" ;;
  esac
}

# The ONE place this file decides what its own run was worth. `verified=no`
# whenever anything was skipped OR the harness caught itself in a defect, and
# the exit status agrees with the token, so a caller cannot pick the convenient
# one of the two.
#
# `skipped=` STAYS LAST. `rails_probe_result` reads a non-empty tail after
# `skipped=` as "this summary names skipped probes", so a field appended after
# it would make every battery read as unverified. New fields go before it.
emit_summary() {
  local verified='yes'
  if [ "$SKIPPED_COUNT" -ne 0 ] || [ "$DEFECTS" -ne 0 ]; then verified='no'; fi
  printf 'PROBE=SUMMARY failures=%s defects=%s skipped_count=%s verified=%s declared=%s ran=%s skipped=%s\n' \
    "$FAILED" "$DEFECTS" "$SKIPPED_COUNT" "$verified" \
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
    report "$p" SKIP '' "precondition unmet: 'sudo -n -u $OPERATOR' is not permitted on this host"
  done
  emit_summary
  printf 'probe-battery: the as-account grant is missing; NOTHING was measured\n' >&2
  exit 2
fi

# ===========================================================================
# THE GATE PORT: HOW A REQUEST REACHES THE SUBJECT AT ALL (round-5 B1)
# ===========================================================================
#
# The exclusive-egress gate is a CONNECT proxy on `127.0.0.1:<gate_port>`. The
# pf anchor passes exactly that loopback destination for the agent uid and
# block-drops the rest; there is NO `rdr`, so nothing is transparently
# redirected. A `curl` that was not pointed at the port did not traverse the
# gate, no matter what it returned. The port is bound per generation
# (`127.0.0.1:0`, bind-first), so it cannot be compiled in either.
#
# The wrapper's `gate-port` verb reads the gate daemon's own published runtime
# state as root and reports `port` + `generation`. Everything here fails
# CLOSED: a port that cannot be learned makes the request UNOBSERVABLE rather
# than making it directly.
GATE_PORT=''
GATE_GENERATION=''
GATE_PORT_STATE='unread'
GATE_PORT_LOG="$EVIDENCE/gate-port.log"
: > "$GATE_PORT_LOG"

learn_gate_port() {
  local cur="$EVIDENCE/.gate-port.current" rc=0 line rest
  GATE_PORT=''
  GATE_GENERATION=''
  GATE_PORT_STATE='unread'
  "$SUDO" -n "$WRAPPER" gate-port \
    --run-id "$RUN_ID" --operator-account "$OPERATOR" \
    --agent-account "$AGENT" --agent-uid "$AGENT_UID" > "$cur" 2>&1 || rc=$?
  "$CAT" "$cur" >> "$GATE_PORT_LOG"
  if [ "$rc" -ne 0 ]; then GATE_PORT_STATE="wrapper-rc-$rc"; return 1; fi
  while IFS= read -r line; do
    case "$line" in
      'WRAPPER=GATE-PORT state=absent'*)
        GATE_PORT_STATE='no-gate-state-published' ;;
      'WRAPPER=GATE-PORT state=present port='*)
        rest="${line#WRAPPER=GATE-PORT state=present port=}"
        GATE_PORT="${rest%% *}"
        rest="${line#* generation=}"
        GATE_GENERATION="${rest%% *}"
        ;;
    esac
  done < "$cur"
  if [ -z "$GATE_PORT" ]; then
    if [ "$GATE_PORT_STATE" = 'unread' ]; then GATE_PORT_STATE='no-port-token-in-wrapper-output'; fi
    return 1
  fi
  # The rail, in the mandatory form. A port that does not pass it is NOT a port
  # this battery aims a request at; it is an unobservable condition.
  GATE_PORT="$(rails_assert_tcp_port "$GATE_PORT")" || {
    GATE_PORT=''; GATE_PORT_STATE='port-token-failed-the-rail'; return 1
  }
  case "$GATE_GENERATION" in
    ''|*[!0-9]*) GATE_PORT=''; GATE_PORT_STATE='generation-token-not-numeric'; return 1 ;;
  esac
  GATE_PORT_STATE='present'
  return 0
}

# THE ONE PLACE A REQUEST IS MADE. Records exactly one observation and sets
# `OBS_ID` (always) and `OBS_CODE` (only when a status code was genuinely
# obtained; empty otherwise, so no caller can mistake "no request" for "000").
#
#   measure_http <probe> <gate|direct> <account> <url>
#
# `gate` proxies to the port the wrapper just reported, and re-reads it
# AFTERWARDS: if the generation rotated across the request, the status code
# belongs to a gate that no longer exists and the observation is recorded
# UNOBSERVABLE rather than attributed to the current generation. That is the
# "assert the port used was the port the current generation committed" half.
#
# `direct` passes `--noproxy '*'` so an ambient proxy variable cannot quietly
# turn a direct request into a through-gate one. `sudo`'s `env_reset` already
# strips it; this makes the channel claim true by construction rather than by
# a property of somebody else's configuration.
measure_http() {
  local probe="$1" channel="$2" acct="$3" url="$4" code before after
  OBS_CODE=''
  case "$channel" in
    gate)
      if ! learn_gate_port; then
        obs_record "$probe" http gate unobservable "gate-port-unavailable:$GATE_PORT_STATE" "$url"
        return 0
      fi
      before="$GATE_PORT:$GATE_GENERATION"
      code="$(as_account "$acct" "$CURL" -sS -o /dev/null -w '%{http_code}' \
        --max-time 15 --connect-timeout 8 \
        --proxy "http://127.0.0.1:$GATE_PORT" "$url" 2>/dev/null || printf '000')"
      if ! learn_gate_port; then
        obs_record "$probe" http gate unobservable \
          "gate-generation-unreadable-after-request:$GATE_PORT_STATE (code was $code)" "$url"
        return 0
      fi
      after="$GATE_PORT:$GATE_GENERATION"
      if [ "$after" != "$before" ]; then
        obs_record "$probe" http gate unobservable \
          "gate-generation-rotated-across-request:$before->$after (code was $code)" "$url"
        return 0
      fi
      OBS_CODE="$code"
      obs_record "$probe" http gate observed "code=$code proxy=127.0.0.1:$GATE_PORT generation=$GATE_GENERATION" "$url"
      ;;
    direct)
      code="$(as_account "$acct" "$CURL" -sS -o /dev/null -w '%{http_code}' \
        --max-time 15 --connect-timeout 8 --noproxy '*' "$url" 2>/dev/null || printf '000')"
      OBS_CODE="$code"
      obs_record "$probe" http direct observed "code=$code noproxy=yes" "$url"
      ;;
    *) die "measure_http: unknown channel '$channel'" ;;
  esac
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
# product actually writes, as root, and reports PER STREAM whether it was read.
GATE_LOG_RC=0
GATE_LOG_GATE_OUT='0,0,0,0'
GATE_LOG_GATE_ERR='0,0,0,0'
GATE_LOG_PEER_OUT='0,0,0,0'
GATE_LOG_PEER_ERR='0,0,0,0'
GATE_LOG_READ_GATE=0
GATE_LOG_READ_PEER=0
capture_gate_log_cursor() {
  local out="$1" rc=0 line rest key cursor
  GATE_LOG_GATE_OUT=''
  GATE_LOG_GATE_ERR=''
  GATE_LOG_PEER_OUT=''
  GATE_LOG_PEER_ERR=''
  "$SUDO" -n "$WRAPPER" gate-log \
    --run-id "$RUN_ID" --operator-account "$OPERATOR" \
    --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
    --log-cursor-only > "$out" 2>&1 || rc=$?
  if [ "$rc" -ne 0 ]; then return "$rc"; fi
  while IFS= read -r line; do
    case "$line" in
      WRAPPER=GATE-LOG-CURSOR\ key=*\ cursor=*\ file=*)
        rest="${line#WRAPPER=GATE-LOG-CURSOR key=}"
        key="${rest%% cursor=*}"
        cursor="${line#* cursor=}"
        cursor="${cursor%% file=*}"
        cursor="$(rails_assert_log_cursor "$cursor")" || return 2
        case "$key" in
          gate_out) GATE_LOG_GATE_OUT="$cursor" ;;
          gate_err) GATE_LOG_GATE_ERR="$cursor" ;;
          peer_out) GATE_LOG_PEER_OUT="$cursor" ;;
          peer_err) GATE_LOG_PEER_ERR="$cursor" ;;
        esac
        ;;
    esac
  done < "$out"
  if [ -z "$GATE_LOG_GATE_OUT" ] || [ -z "$GATE_LOG_GATE_ERR" ] || \
     [ -z "$GATE_LOG_PEER_OUT" ] || [ -z "$GATE_LOG_PEER_ERR" ]; then
    return 2
  fi
  return 0
}

read_gate_log_since_cursor() {
  local out="$1" line
  GATE_LOG_RC=0
  GATE_LOG_READ_GATE=0
  GATE_LOG_READ_PEER=0
  "$SUDO" -n "$WRAPPER" gate-log \
    --run-id "$RUN_ID" --operator-account "$OPERATOR" \
    --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
    --since-gate-out "$GATE_LOG_GATE_OUT" \
    --since-gate-err "$GATE_LOG_GATE_ERR" \
    --since-peer-out "$GATE_LOG_PEER_OUT" \
    --since-peer-err "$GATE_LOG_PEER_ERR" \
    > "$out" 2>&1 || GATE_LOG_RC=$?
  # ROUND-5 M3. Which STREAMS were actually read, per key, from the wrapper's
  # own per-stream report. The verb exits 0 if ANY of the four was readable,
  # and the four are not interchangeable: the gate daemon writes the denial
  # reasons, the peer resolver does not.
  #
  # PARSING STOPS AT THE SENTINEL, and that is the point rather than tidiness.
  # Everything after `WRAPPER=GATE-LOG-CONTENT-BEGIN` is LOG CONTENT written by
  # the gate service uid. A log line that happened to read
  # `WRAPPER=GATE-LOG-READ key=gate_out state=read` would otherwise tell this
  # driver that a stream had been read that had not -- the round-5 L2 class (a
  # machine token trusted from inside a content region) recreated while closing
  # round-5 M3. The wrapper emits all four verdicts BEFORE any content, and this
  # loop refuses to look past the boundary.
  while IFS= read -r line; do
    case "$line" in
      'WRAPPER=GATE-LOG-CONTENT-BEGIN') break ;;
      'WRAPPER=GATE-LOG-READ key=gate_out state=read'|'WRAPPER=GATE-LOG-READ key=gate_err state=read')
        GATE_LOG_READ_GATE=$((GATE_LOG_READ_GATE + 1)) ;;
      'WRAPPER=GATE-LOG-READ key=peer_out state=read'|'WRAPPER=GATE-LOG-READ key=peer_err state=read')
        GATE_LOG_READ_PEER=$((GATE_LOG_READ_PEER + 1)) ;;
    esac
  done < "$out"
  return 0
}

# Did the gate log carry <pattern>? Three answers, never two:
#   0  observed, and it matched
#   1  observed, and it did not match
#   2  COULD NOT OBSERVE (the stream that would carry this pattern was not read)
#
# `class` names WHICH stream would have carried the pattern. Every denial
# reason in this ladder -- `allowlist`, `peer=`, `peer_unresolved`,
# `peer_uid_mismatch` -- is written by the GATE DAEMON, so `gate` is what they
# ask for. A readable peer-resolver log is not evidence about them.
gate_log_since_says() {
  local class="$1" pattern="$2" evidence="$3"
  read_gate_log_since_cursor "$evidence"
  if [ "$GATE_LOG_RC" -ne 0 ]; then return 2; fi
  case "$class" in
    gate) [ "$GATE_LOG_READ_GATE" -gt 0 ] || return 2 ;;
    peer) [ "$GATE_LOG_READ_PEER" -gt 0 ] || return 2 ;;
    any)  [ $((GATE_LOG_READ_GATE + GATE_LOG_READ_PEER)) -gt 0 ] || return 2 ;;
    *) die "gate_log_since_says: unknown stream class '$class'" ;;
  esac
  # -F: these patterns are LITERAL tokens, and a path or uid read as a
  # regular expression could match something adjacent to what was meant.
  if "$GREP" -q -F -- "$pattern" "$evidence"; then return 0; fi
  return 1
}

# The ledger-recording wrapper around it. Sets `OBS_ID`, and `OBS_MATCH` to
# `yes` / `no` / `''` (the last meaning the stream could not be observed).
OBS_MATCH=''
measure_gate_log() {
  local probe="$1" class="$2" pattern="$3" evidence="$4" rc=0
  OBS_MATCH=''
  gate_log_since_says "$class" "$pattern" "$evidence" || rc=$?
  case "$rc" in
    0) OBS_MATCH='yes'
       obs_record "$probe" gatelog - observed "match streams=$class rc=$GATE_LOG_RC" "$pattern" ;;
    1) OBS_MATCH='no'
       obs_record "$probe" gatelog - observed "no-match streams=$class rc=$GATE_LOG_RC" "$pattern" ;;
    *) obs_record "$probe" gatelog - unobservable \
         "stream-class-$class-not-read (wrapper rc=$GATE_LOG_RC, gate=$GATE_LOG_READ_GATE peer=$GATE_LOG_READ_PEER)" "$pattern" ;;
  esac
}

# --- P1: positive through-gate, N repeats ---------------------------------
p1_basis=''
p1_attempts=0
p1_fail=0
p1_cursor_rc=0
capture_gate_log_cursor "$EVIDENCE/gate-log-p1.cursor" || p1_cursor_rc=$?
for url in $ALLOWED; do
  i=1
  while [ "$i" -le "$REPEATS" ]; do
    measure_http P1 gate "$AGENT" "$url"
    p1_basis="$p1_basis,$OBS_ID"
    printf 'p1 url=%s attempt=%s obs=%s code=%s\n' "$url" "$i" "$OBS_ID" "${OBS_CODE:-<not-observed>}" \
      >> "$EVIDENCE/p1-through-gate.log"
    if [ -n "$OBS_CODE" ]; then
      p1_attempts=$((p1_attempts + 1))
      case "$OBS_CODE" in
        2*|3*) ;;
        *) p1_fail=$((p1_fail + 1)) ;;
      esac
    fi
    i=$((i + 1))
  done
done
if [ "$p1_attempts" -eq 0 ]; then
  report P1 UNOBSERVED '' "no request could be aimed at the gate for this agent (gate port: $GATE_PORT_STATE); nothing about reachability was measured"
elif [ "$p1_fail" -eq 0 ]; then
  report P1 PASS "${p1_basis#,}" "allowed endpoints reachable through the gate, attempts=$p1_attempts"
else
  report P1 FAIL "${p1_basis#,}" "$p1_fail of $p1_attempts through-gate attempts did not succeed"
fi

# The reason half of P1: the gate must have RESOLVED the peer uid. A green
# status code with peer_unresolved in the log is the 2026-07-24 strangle
# wearing a passing costume.
#
# THREE outcomes, not two. "the log says the peer resolved" (PASS), "the log
# says peer_unresolved" (FAIL) and "there is no gate-daemon log to read"
# (UNOBSERVED, which makes the whole battery unverified) are different facts
# and are reported as different facts.
if [ "$p1_cursor_rc" -ne 0 ]; then
  report P1-reason UNOBSERVED '' "could not take a gate-log cursor before P1 (wrapper gate-log rc=$p1_cursor_rc); the reason half CANNOT be evaluated"
else
  measure_gate_log P1-reason gate "peer=$AGENT_UID" "$EVIDENCE/gate-log-p1.txt"
  p1r_basis="$OBS_ID"
  case "$OBS_MATCH" in
    yes) report P1-reason PASS "$p1r_basis" "gate resolved peer=$AGENT_UID in bytes appended during P1" ;;
    no)
      measure_gate_log P1-reason gate 'peer_unresolved' "$EVIDENCE/gate-log-p1.txt"
      p1r_basis="$p1r_basis,$OBS_ID"
      case "$OBS_MATCH" in
        yes) report P1-reason FAIL "$p1r_basis" 'the gate log window for P1 shows peer_unresolved; the peer resolver is not working' ;;
        no)  report P1-reason FAIL "$p1r_basis" "the gate log window for P1 carries no peer field for uid $AGENT_UID; the through-gate status codes cannot be attributed to a resolved peer" ;;
        *)   report P1-reason UNOBSERVED '' "the gate daemon's log could not be read after P1 (wrapper gate-log rc=$GATE_LOG_RC); the reason half CANNOT be evaluated" ;;
      esac
      ;;
    *) report P1-reason UNOBSERVED '' "the gate daemon's log could not be read after P1 (wrapper gate-log rc=$GATE_LOG_RC); the reason half CANNOT be evaluated" ;;
  esac
fi

# --- N1: off-manifest endpoint denied, for the right reason ---------------
for url in $BLOCKED; do
  n1_cursor_rc=0
  capture_gate_log_cursor "$EVIDENCE/gate-log-n1.cursor" || n1_cursor_rc=$?
  measure_http N1 gate "$AGENT" "$url"
  n1_basis="$OBS_ID"
  n1_code="$OBS_CODE"
  printf 'n1 url=%s obs=%s code=%s\n' "$url" "$OBS_ID" "${n1_code:-<not-observed>}" \
    >> "$EVIDENCE/n1-off-manifest.log"
  if [ -z "$n1_code" ]; then
    report N1 UNOBSERVED '' "no request could be aimed at the gate for off-manifest $url (gate port: $GATE_PORT_STATE)"
  elif [ "$n1_code" = '000' ] || [ "$n1_code" = '403' ]; then
    if [ "$n1_cursor_rc" -ne 0 ]; then
      report N1 UNOBSERVED '' "off-manifest $url was denied (code $n1_code) but the gate-log cursor could not be taken first (rc=$n1_cursor_rc), so the REASON is unmeasured"
    else
      measure_gate_log N1 gate 'allowlist' "$EVIDENCE/gate-log-n1.txt"
      n1_basis="$n1_basis,$OBS_ID"
      case "$OBS_MATCH" in
        yes) report N1 PASS "$n1_basis" "off-manifest $url denied by the allowlist in the current log window" ;;
        no)  report N1 FAIL "$n1_basis" "off-manifest $url denied (code $n1_code) but not for an allowlist reason in the current log window" ;;
        *)   report N1 UNOBSERVED '' "off-manifest $url was denied (code $n1_code) but the gate daemon's log could not be READ (rc=$GATE_LOG_RC), so the REASON is unmeasured" ;;
      esac
    fi
  else
    report N1 FAIL "$n1_basis" "off-manifest $url returned $n1_code; expected a denial"
  fi
done

# --- N3: a valid request from the WRONG uid must be denied AT THE GATE ----
#
# ROUND-5 B1. This probe used to issue a BARE curl as the operator. The
# operator is unconfined (that is what P2 asserts), so the request went
# straight out, returned 200, and N3 reported a failure that had nothing to do
# with the gate -- while `peer_uid_mismatch`, which the gate emits ONLY for a
# socket connected to the gate port, could never appear. N3 and P2 were also
# mutually contradictory as written: P2 required the operator to reach the
# network and N3 required the operator to be denied, and no host state
# satisfies both. The distinction is the CHANNEL, and now the code carries it:
# P2 measures the operator DIRECT, N3 measures the operator THROUGH THE GATE.
#
# ROUND-5 M2. The verdict then read `$code`, a plain shell variable last
# written by the N1 loop, so with an empty endpoint list N3 reported on a
# request it had never made. `measure_http` sets `OBS_CODE` on every call and
# empties it first, and the basis id is this probe's own record; a verdict
# built from another probe's observation is refused by `report`.
n3_cursor_rc=0
n3_basis=''
n3_code=''
n3_url=''
capture_gate_log_cursor "$EVIDENCE/gate-log-n3.cursor" || n3_cursor_rc=$?
for url in $ALLOWED; do
  measure_http N3 gate "$OPERATOR" "$url"
  n3_basis="$OBS_ID"
  n3_code="$OBS_CODE"
  n3_url="$url"
  printf 'n3 url=%s obs=%s operator_code=%s\n' "$url" "$OBS_ID" "${n3_code:-<not-observed>}" \
    >> "$EVIDENCE/n3-wrong-uid.log"
  break
done
if [ -z "$n3_basis" ]; then
  report N3 UNOBSERVED '' 'there was no allowed endpoint to aim a wrong-uid request at; nothing was measured'
elif [ -z "$n3_code" ]; then
  report N3 UNOBSERVED '' "the wrong-uid request could not be aimed at the gate (gate port: $GATE_PORT_STATE); nothing was measured"
elif [ "$n3_code" != '000' ] && [ "$n3_code" != '403' ]; then
  # Deliberately NOT naming the log token here. This verdict rests on the
  # status code alone, and its basis is one http observation; a text that named
  # a log reason would be claiming a mechanism this basis never exercised, and
  # `report` would (correctly) refuse it as a harness defect.
  report N3 FAIL "$n3_basis" "a request from the wrong uid SUCCEEDED with code $n3_code; a denial reason recorded anywhere else cannot make this pass"
elif [ "$n3_cursor_rc" -ne 0 ]; then
  report N3 UNOBSERVED '' "wrong-uid $n3_url was denied (code $n3_code) but the gate-log cursor could not be taken first (rc=$n3_cursor_rc), so the REASON is unmeasured"
else
  measure_gate_log N3 gate 'peer_uid_mismatch' "$EVIDENCE/gate-log-n3.txt"
  n3_basis="$n3_basis,$OBS_ID"
  case "$OBS_MATCH" in
    yes) report N3 PASS "$n3_basis" 'the current request from a non-agent uid was denied with peer_uid_mismatch' ;;
    no)  report N3 FAIL "$n3_basis" 'the gate-log window for the non-agent request shows no peer_uid_mismatch; a denial for an unobserved reason is the 2026-07-24 false-green class' ;;
    *)   report N3 UNOBSERVED '' "the gate daemon's log could not be READ after the wrong-uid request (wrapper gate-log rc=$GATE_LOG_RC); the wrong-uid denial reason CANNOT be evaluated" ;;
  esac
fi

# --- P2: per-uid differential, on the DIRECT path ------------------------
# The operator must reach a destination the AGENT is blocked from, WITHOUT the
# gate. That is what makes the confinement per-uid rather than host-wide, and
# it is a different question from N3 (see the note above).
p2_basis=''
p2_attempts=0
op_blocked=0
for url in $BLOCKED; do
  measure_http P2-operator direct "$OPERATOR" "$url"
  p2_basis="$p2_basis,$OBS_ID"
  printf 'p2 operator url=%s obs=%s code=%s\n' "$url" "$OBS_ID" "${OBS_CODE:-<not-observed>}" \
    >> "$EVIDENCE/p2-differential.log"
  if [ -n "$OBS_CODE" ]; then
    p2_attempts=$((p2_attempts + 1))
    case "$OBS_CODE" in
      2*|3*) ;;
      *) op_blocked=$((op_blocked + 1)) ;;
    esac
  fi
done
if [ "$p2_attempts" -eq 0 ]; then
  report P2-operator UNOBSERVED '' 'no direct request was made from the operator uid; the per-uid differential is unmeasured'
elif [ "$op_blocked" -eq 0 ]; then
  report P2-operator PASS "${p2_basis#,}" "operator uid $OPERATOR_UID reached every blocked destination directly across $p2_attempts attempts; it is unconfined"
else
  report P2-operator FAIL "${p2_basis#,}" "operator uid $OPERATOR_UID was blocked on $op_blocked of $p2_attempts direct attempts; the wall is confining the wrong account"
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
obs_record P3 wrapper - observed "second-arm-rc=$p3_arm_rc" 'wrapper arm'
p3_basis="$OBS_ID"
if [ "$p3_arm_rc" -eq 0 ]; then
  report P3 FAIL "$p3_basis" 'a second exclusive arm over a live confined agent SUCCEEDED; it must be refused'
else
  p3_attempts=0
  p3_dead=0
  for url in $ALLOWED; do
    measure_http P3 gate "$AGENT" "$url"
    p3_basis="$p3_basis,$OBS_ID"
    printf 'p3 post-refusal url=%s obs=%s code=%s\n' "$url" "$OBS_ID" "${OBS_CODE:-<not-observed>}" \
      >> "$EVIDENCE/p3-second-arm.log"
    if [ -n "$OBS_CODE" ]; then
      p3_attempts=$((p3_attempts + 1))
      case "$OBS_CODE" in 2*|3*) ;; *) p3_dead=$((p3_dead + 1)) ;; esac
    fi
  done
  if [ "$p3_attempts" -eq 0 ]; then
    report P3 UNOBSERVED '' "the second arm was refused (rc=$p3_arm_rc) but no request could be aimed at the gate afterwards (gate port: $GATE_PORT_STATE), so survival is unmeasured"
  elif [ "$p3_dead" -eq 0 ]; then
    report P3 PASS "$p3_basis" "the second arm was refused (rc=$p3_arm_rc) and the live gate survived it across $p3_attempts through-gate attempts"
  else
    report P3 FAIL "$p3_basis" "the second arm was refused (rc=$p3_arm_rc) but $p3_dead of $p3_attempts through-gate attempts failed afterwards; the live gate did NOT survive it"
  fi
fi

# --- F1/F2: gate-port rotation settles AND the agent survives -------------
# This is the class the 2026-07-25 drill found: repair rotated pf and the
# resolver to a new port but never restarted the gate daemon, so the agent was
# confined to a port nothing served. Fail-closed, and still a failure.
#
# Every post-rotation request re-learns the port, which is the only way this
# probe can mean anything: the whole point of a rotation is that the old port
# is gone.
rot=1
rot_basis=''
rot_cycles=0
rot_fail=0
while [ "$rot" -le "$REPEATS" ]; do
  rot_rc=0
  "$SUDO" -n "$WRAPPER" repair \
    --run-id "$RUN_ID" --operator-account "$OPERATOR" \
    --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
    >> "$EVIDENCE/f1-rotation.log" 2>&1 || rot_rc=$?
  obs_record F1-F2 wrapper - observed "rotation=$rot repair-rc=$rot_rc" 'wrapper repair'
  rot_basis="$rot_basis,$OBS_ID"
  if [ "$rot_rc" -ne 0 ]; then
    rot_cycles=$((rot_cycles + 1))
    rot_fail=$((rot_fail + 1))
    printf 'f1 rotation=%s repair exited %s\n' "$rot" "$rot_rc" >> "$EVIDENCE/f1-rotation.log"
  else
    # F2: the agent must still work after the rotation.
    post_attempts=0
    post_dead=0
    for url in $ALLOWED; do
      measure_http F1-F2 gate "$AGENT" "$url"
      rot_basis="$rot_basis,$OBS_ID"
      printf 'f2 rotation=%s url=%s obs=%s code=%s\n' "$rot" "$url" "$OBS_ID" "${OBS_CODE:-<not-observed>}" \
        >> "$EVIDENCE/f1-rotation.log"
      if [ -n "$OBS_CODE" ]; then
        post_attempts=$((post_attempts + 1))
        case "$OBS_CODE" in 2*|3*) ;; *) post_dead=$((post_dead + 1)) ;; esac
      fi
    done
    if [ "$post_attempts" -eq 0 ]; then
      printf 'f2 rotation=%s NOT MEASURED (%s)\n' "$rot" "$GATE_PORT_STATE" >> "$EVIDENCE/f1-rotation.log"
    else
      rot_cycles=$((rot_cycles + 1))
      if [ "$post_dead" -ne 0 ]; then
        rot_fail=$((rot_fail + 1))
        printf 'f2 rotation=%s STRANGLED the agent\n' "$rot" >> "$EVIDENCE/f1-rotation.log"
      fi
    fi
  fi
  rot=$((rot + 1))
done
if [ "$rot_cycles" -eq 0 ]; then
  report F1-F2 UNOBSERVED '' "no rotation cycle could be measured end to end (gate port: $GATE_PORT_STATE); neither settling nor survival was established"
elif [ "$rot_fail" -eq 0 ]; then
  report F1-F2 PASS "${rot_basis#,}" "gate-port rotation settled and the agent stayed functional through the gate across $rot_cycles measured cycles"
else
  report F1-F2 FAIL "${rot_basis#,}" "$rot_fail of $rot_cycles measured rotation cycles failed or strangled the agent"
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
    *) report "$p" SKIP '' 'declared but never reported; the battery did not reach it' ;;
  esac
done

emit_summary
# A HARNESS DEFECT outranks everything else: it means this file attempted a
# verdict its own observations could not justify, so nothing it says about the
# host can be relied on. Distinct status, so no caller can read it as either a
# clean night or an ordinary probe failure.
if [ "$DEFECTS" -ne 0 ]; then
  printf 'probe-battery: %s verdict(s) were refused by the observation ledger; this run measured less than it tried to claim\n' "$DEFECTS" >&2
  exit 4
fi
if [ "$FAILED" -ne 0 ]; then exit 1; fi
# UNVERIFIED. Distinct from both green and failed, and NONZERO, so no caller can
# turn a skipped declared probe into a pass by reading only the exit status.
if [ "$SKIPPED_COUNT" -ne 0 ]; then exit 3; fi
