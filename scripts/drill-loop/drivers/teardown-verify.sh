#!/usr/bin/env bash
#
# teardown-verify.sh - tear the iteration down, then verify OBSERVED state.
#
# The rule this script exists to enforce: a recovery path must VERIFY, not
# REPORT. `--unprotect-egress-gate` exiting 0 is a claim, not evidence. This
# script re-reads the world afterwards and only then says clean:
#
#   * the registry no longer references this storage path
#   * the pf anchor carries no rules
#   * the exclusive-routing marker is gone
#   * no lock files are left behind, and in particular no zero-length ones
#   * the agent uid is unconfined again
#   * and the disposable fortress itself is retired
#
# A CHECK THAT COULD NOT OBSERVE IS NOT A CLEAN CHECK. The reviewed build did
# `rules="$(sudo -n pfctl ... || printf '')"` and read the empty string as
# CLEAN, while the README said plainly that the pfctl grant does not exist. On
# the first unattended night that check would have reported CLEAN having
# observed nothing at all.
#
# ROUND 3 FOUND THAT RULE APPLIED IN TWO PLACES AND MISSED IN THREE. Every check
# below is now explicitly TRI-STATE:
#
#   OBSERVED-CLEAN     the observation was made and it was clean
#   OBSERVED-DIRTY     the observation was made and state was left behind
#   COULD-NOT-OBSERVE  the observation could not be made at all
#
# The third is a HARD FAILURE and is never folded into either of the others. It
# is reported as `VERIFY=UNOBSERVED`, which is a distinct token from
# `VERIFY=DIRTY`, so a reader can tell "the host is dirty" from "this harness is
# blind" -- two very different mornings.
#
# The registry and the in-fortress marker/lock reads now go through ROOT wrapper
# verbs (`registry-state`, `fortress-state`), because the things they look at
# are root-owned 0600/0700 and an unprivileged read of them returns exactly what
# "clean" used to look like.
#
# A failure here is one of the loop's TWO stop-the-night exceptions. Continuing
# past a dirty teardown wedges the host and every later iteration is born
# tainted, so the loop stops rather than compounding state.
#
# AND THE TEARDOWN VERB'S OWN EXIT STATUS IS NOT THAT FAILURE. A verb that
# refused because there was nothing armed to unprotect, on a host every one of
# the checks below observed and found clean, is not a failed teardown; see the
# long note at the verdict block near the end of this file. The stop-the-night
# rule itself is unchanged: any dirt, any check that could not observe, and any
# uncontrolled exit still stop the night.
#
# Usage: teardown-verify.sh --run-id <id> --operator-account <a>
#          --agent-account <a> --agent-uid <n> --evidence-dir <d> [--base <dir>]
#          [--no-retire]
# Exit:  0 torn down (or nothing to tear down) and verified clean by observed
#        state; 1 dirty, unobservable, or a teardown that did not merely refuse
#        (STOP THE NIGHT); 2 usage

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(CDPATH='' cd -P -- "$HERE/.." && pwd -P)"
# shellcheck source=../lib/rails.sh
. "$ROOT/lib/rails.sh"

WRAPPER='/usr/local/sbin/sanctuary-drill-wrapper'

die() {
  printf 'teardown-verify: %s\n' "$*" >&2
  exit 2
}

# ROUND-3 BLOCKER 1. See the long note in run-probe-battery.sh: a planted `sudo`
# earlier in PATH produced a completely clean teardown verdict for a teardown
# that never happened. Every tool this file's verdict rests on is resolved once,
# absolutely, and PATH is pinned as a belt rather than as the defense.
PATH="$RAILS_SYSTEM_PATH"
export PATH
SUDO="$(rails_require_cmd sudo)" || die 'sudo is not in a root-owned system directory; refusing to verify a teardown through an unresolvable tool'
CURL="$(rails_require_cmd curl)" || die 'curl is not in a root-owned system directory'
GREP="$(rails_require_cmd grep)" || die 'grep is not in a root-owned system directory'
MKDIR="$(rails_require_cmd mkdir)" || die 'mkdir is not in a root-owned system directory'

RUN_ID=''
OPERATOR=''
AGENT=''
AGENT_UID_IN=''
EVIDENCE=''
# See the note in preflight.sh: this driver is unprivileged and the root
# wrapper takes no base argument, so a --base here cannot redirect anything
# that runs as root. It exists so the batteries can drive this file end to end.
BASE="$RAILS_DISPOSABLE_BASE"
RETIRE='yes'

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id)           RUN_ID="${2:-}"; shift 2 ;;
    --operator-account) OPERATOR="${2:-}"; shift 2 ;;
    --agent-account)    AGENT="${2:-}"; shift 2 ;;
    --agent-uid)        AGENT_UID_IN="${2:-}"; shift 2 ;;
    --evidence-dir)     EVIDENCE="${2:-}"; shift 2 ;;
    --base)             BASE="${2:-}"; shift 2 ;;
    --no-retire)        RETIRE=''; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$EVIDENCE" ] || die '--evidence-dir is required'
[ -n "$RUN_ID" ] || die '--run-id is required'
"$MKDIR" -p "$EVIDENCE"

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

LOG="$EVIDENCE/teardown.log"

# --- tear down ------------------------------------------------------------
#
# The output is CAPTURED rather than appended straight into "$LOG", because the
# refusal marker in it is load-bearing for the verdict below and "$LOG" is also
# this script's own stdout target when run-loop.sh drives it. Every other
# verdict-bearing read in this file already works this way.
TEARDOWN_RC=0
teardown_out="$("$SUDO" -n "$WRAPPER" unprotect \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" \
  --agent-account "$AGENT" --agent-uid "$AGENT_UID" 2>&1)" || TEARDOWN_RC=$?
printf 'unprotect rc=%s:\n%s\n' "$TEARDOWN_RC" "$teardown_out" >> "$LOG"
printf 'TEARDOWN rc=%s\n' "$TEARDOWN_RC"

# DID THE RAIL SAY NO, or did the command blow up? Two different facts, and the
# reviewed build had one exit-code test for both.
#
# `RAILS_REJECT_STATUS` (20) is the status EVERY controlled refusal exits with,
# and a controlled refusal is by construction a statement that the wrapper did
# NOT reach the CLI. But the status alone is not sufficient evidence of that:
# `wrapper_cli` execs the product CLI as the verb's last command, so a product
# CLI that itself exited 20 would surface here as the identical number with a
# completely different meaning. The wrapper prints a machine-readable marker on
# every refusal path (`WRAPPER=REJECT`, or `RAILS_REJECT` from the rails), so
# the status is corroborated by the marker rather than trusted on its own. rc=20
# with no marker is an exit code that came from somewhere else, and is treated
# as an error.
TEARDOWN_REFUSED=''
case "$teardown_out" in
  *'WRAPPER=REJECT reason='*|*'RAILS_REJECT: '*) TEARDOWN_REFUSED='yes' ;;
esac

CLEAN_MARKERS_RC=0
"$SUDO" -n "$WRAPPER" clean-markers \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" \
  >> "$LOG" 2>&1 || CLEAN_MARKERS_RC=$?
printf 'CLEAN_MARKERS rc=%s\n' "$CLEAN_MARKERS_RC"

# --- verify OBSERVED state, whatever the teardown claimed -----------------
#
# THREE verdicts, and the third one is the round-3 fix. `clean_unobserved` is
# NOT `clean_fail` with a different message: it is a distinct token so the
# morning can tell "the host is dirty" from "this harness is blind", and it is
# counted separately so neither number can be read as the other. Both stop the
# night; only one of them means there is state to clean up.
DIRTY=0
UNOBSERVED=0
clean_pass() { printf 'VERIFY=CLEAN check=%s %s\n' "$1" "${2:-}"; }
clean_fail() {
  printf 'VERIFY=DIRTY check=%s reason=%s\n' "$1" "$2"
  DIRTY=$((DIRTY + 1))
}
clean_unobserved() {
  printf 'VERIFY=UNOBSERVED check=%s reason=%s\n' "$1" "$2"
  UNOBSERVED=$((UNOBSERVED + 1))
}

# --- the pf-anchor REGISTRY, read as root ---------------------------------
#
# ROUND-3 H1 / Codex finding 3, and this is the one where correcting the path
# alone would have made things look worse and be no better. The reviewed code
# was
#
#   if [ -f "$registry" ] && grep -q -- "$STORAGE" "$registry" 2>/dev/null
#   then dirty; else CLEAN; fi
#
# against `/Library/Application Support/Sanctuary/egress-gate/registry.json`,
# which appears NOWHERE in server/src. The product's registry is
# `/var/db/sanctuary/egress-anchor-registry.json`, root-owned 0600 inside a 0700
# directory -- so with the path corrected, an unprivileged `grep` returns 2 and
# the SAME `else` branch still prints CLEAN. "no match", "cannot read" and "not
# there" were one verdict, and two of the three are not clean.
REGISTRY_RC=0
registry_out="$("$SUDO" -n "$WRAPPER" registry-state \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" 2>&1)" || REGISTRY_RC=$?
printf 'registry read rc=%s:\n%s\n' "$REGISTRY_RC" "$registry_out" >> "$LOG"
# ROUND-5 L2, taken past the token swap. The verb prints the registry file's
# own BYTES between REGISTRY-BEGIN and REGISTRY-END, and its VERDICT after
# them. A `grep` over the combined output therefore reads a machine token out
# of a CONTENT REGION -- which is the defect, not the particular token, and
# just renaming the token would have left it. The verdict is always the LAST
# `WRAPPER=OK verb=registry-state state=` line by construction (content is
# printed before it), so that is what is read. Pure shell, no external
# command: every tool a driver's evidence rests on must be absolutely
# resolved, and a bare `tail` here would be the round-3 BLOCKER-1 shape.
registry_verdict=''
while IFS= read -r _rline; do
  case "$_rline" in
    'WRAPPER=OK verb=registry-state state='*)
      _rline="${_rline#WRAPPER=OK verb=registry-state state=}"
      registry_verdict="${_rline%% *}"
      ;;
  esac
done <<REGISTRY_VERDICT_EOF
$registry_out
REGISTRY_VERDICT_EOF

if [ "$REGISTRY_RC" -ne 0 ]; then
  clean_unobserved registry "could not READ the pf-anchor registry (rc=$REGISTRY_RC); an unread registry is not a clean registry"
elif [ "$registry_verdict" = 'absent' ]; then
  # ROUND-5 L2, same as preflight.sh: key on the verb's single-line VERDICT,
  # never on a token that can also appear inside the content region it prints.
  clean_pass registry 'no registry file on this host'
elif printf '%s\n' "$registry_out" | "$GREP" -q -F -- "$STORAGE"; then
  clean_fail registry "the registry still references $STORAGE"
elif printf '%s\n' "$registry_out" | "$GREP" -q '^WRAPPER=REGISTRY-END'; then
  clean_pass registry 'read, and it does not reference this fortress'
else
  clean_unobserved registry 'the registry-state verb exited 0 without a REGISTRY-END marker; the read cannot be trusted'
fi

# THE FAIL-OPEN THAT WAS. This goes through a wrapper verb, which the NOPASSWD
# grant already covers, so it needs no second grant; and the verb exits nonzero
# when pfctl itself could not run, so "refused", "errored" and "empty anchor"
# are three different answers instead of one empty string.
ANCHOR_RC=0
anchor_out="$("$SUDO" -n "$WRAPPER" pf-anchor-rules \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" 2>&1)" || ANCHOR_RC=$?
printf 'pf anchor read rc=%s:\n%s\n' "$ANCHOR_RC" "$anchor_out" >> "$LOG"
if [ "$ANCHOR_RC" -ne 0 ]; then
  clean_unobserved pf-anchor "could not READ the pf anchor (rc=$ANCHOR_RC); a check that observed nothing is not a clean verdict"
else
  anchor_rules="$(printf '%s\n' "$anchor_out" \
    | rails__sys sed -n '/WRAPPER=PF-ANCHOR-BEGIN/,/WRAPPER=PF-ANCHOR-END/p' \
    | rails__sys grep -v 'WRAPPER=PF-ANCHOR-' || printf '')"
  if [ -n "$(printf '%s' "$anchor_rules" | rails__sys tr -d ' \t\n\r')" ]; then
    clean_fail pf-anchor 'pf anchor still carries rules'
  else
    clean_pass pf-anchor
  fi
fi

# --- the fortress's own marker and lock files, read AS ROOT ----------------
#
# The unprivileged version of this could not be made to work, and saying so was
# the previous round's honest stopgap. `tightenStoragePermissions` chmods the
# fortress to 0700 on every server start and the fortress is root-owned, so from
# the first arm onward this process cannot look inside it at all. Absence and
# not-allowed-to-look are the same observation from here, and absence is what
# these checks call clean.
#
# Root can look. `fortress-state` names a state for every entry, and there is no
# state that means "I did not look" -- an entry the verb could not classify
# makes the verb fail, and a verb that failed is UNOBSERVED here.
FORTRESS_RC=0
fortress_out="$("$SUDO" -n "$WRAPPER" fortress-state \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" 2>&1)" || FORTRESS_RC=$?
printf 'fortress-state rc=%s:\n%s\n' "$FORTRESS_RC" "$fortress_out" >> "$LOG"

fortress_entry_state() {
  local line
  line="$(printf '%s\n' "$fortress_out" | "$GREP" -m1 "^FORTRESS entry=$1 state=" || printf '')"
  if [ -z "$line" ]; then printf ''; return 0; fi
  printf '%s' "${line##*state=}"
}

if [ "$FORTRESS_RC" -ne 0 ]; then
  # ONE unobserved finding, not three clean ones.
  clean_unobserved fortress-state "could not READ the disposable fortress through the wrapper (rc=$FORTRESS_RC); the marker and lock checks CANNOT be made, and their absence-means-clean logic would report CLEAN having observed nothing"
elif ! printf '%s\n' "$fortress_out" | "$GREP" -q '^WRAPPER=FORTRESS-END'; then
  clean_unobserved fortress-state 'the fortress-state verb exited 0 without a FORTRESS-END marker; the read cannot be trusted'
else
  clean_pass fortress-state "$STORAGE"

  marker_state="$(fortress_entry_state 'exclusive-routing.json')"
  case "$marker_state" in
    absent)  clean_pass marker ;;
    '')      clean_unobserved marker 'the fortress read carried no state for exclusive-routing.json' ;;
    *)       clean_fail marker "exclusive-routing.json survived teardown (state=$marker_state)" ;;
  esac

  left_locks=''
  unread_locks=''
  for rel in 'state/_audit/.audit-write.lock' 'state/.provision.lock'; do
    lock_state="$(fortress_entry_state "$rel")"
    case "$lock_state" in
      absent) ;;
      '')     unread_locks="$unread_locks $rel" ;;
      *)      left_locks="$left_locks $rel(state=$lock_state)" ;;
    esac
  done
  if [ -n "$unread_locks" ]; then
    clean_unobserved locks "the fortress read carried no state for:$unread_locks"
  elif [ -n "$left_locks" ]; then
    clean_fail locks "lock file(s) survived teardown:$left_locks"
  else
    clean_pass locks
  fi
fi

# The agent uid must be free again. A teardown that leaves the agent confined
# is exactly as broken as one that leaves the gate armed, it just fails in the
# direction that looks safe.
#
# `sudo -n -u <agent>` is NOT covered by the reviewed NOPASSWD grant (see
# sudoers.d/sanctuary-drill, which records why widening it is not the answer).
# So the two failure modes are told apart: a refused sudo is reported as an
# observation that could not be made, not as a confined agent and not as a
# clean one.
AGENT_PROBE_RC=0
agent_code="$("$SUDO" -n -u "$AGENT" "$CURL" -sS -o /dev/null -w '%{http_code}' \
  --max-time 15 --connect-timeout 8 https://example.com 2>>"$LOG")" || AGENT_PROBE_RC=$?
printf 'post-teardown agent status=%s probe_rc=%s\n' "${agent_code:-<none>}" "$AGENT_PROBE_RC" >> "$LOG"
if [ "$AGENT_PROBE_RC" -ne 0 ] && [ -z "$agent_code" ]; then
  clean_unobserved agent-unconfined "could not RUN the as-agent probe (sudo -n -u $AGENT rc=$AGENT_PROBE_RC); the grant for it does not exist, so this check observed nothing"
else
  case "$agent_code" in
    2*|3*) clean_pass agent-unconfined "agent uid $AGENT_UID reaches the network again" ;;
    *)     clean_fail agent-unconfined "agent uid $AGENT_UID still cannot reach the network (code ${agent_code:-000})" ;;
  esac
fi

# --- retire the disposable fortress ---------------------------------------
#
# ROUND-3 M1: nothing removed these, ever, while the README said the loop "tears
# it down each night". That is unbounded accumulation of root-owned directories
# under the base, one per iteration forever. Retirement runs LAST, after every
# observation has been made, so it can never destroy the evidence the checks
# above are drawing their verdicts from.
RETIRE_RC=0
if [ -n "$RETIRE" ]; then
  "$SUDO" -n "$WRAPPER" retire \
    --run-id "$RUN_ID" --operator-account "$OPERATOR" \
    >> "$LOG" 2>&1 || RETIRE_RC=$?
  if [ "$RETIRE_RC" -eq 0 ]; then
    clean_pass retire "$STORAGE removed"
  else
    clean_fail retire "the disposable fortress could not be retired (rc=$RETIRE_RC); root-owned directories would accumulate under $BASE"
  fi
else
  printf 'VERIFY=SKIPPED check=retire reason=--no-retire was passed\n'
fi

# --- what the teardown VERB's exit status means, decided from OBSERVED state -
#
# THE 2026-07-25 ROUND-3 LIVE RUN, ONE RUNG BELOW THE TWO ALREADY FIXED. The
# night stopped on
#
#   TEARDOWN rc=20
#   VERIFY=SUMMARY dirty=0 unobserved=0 teardown_rc=20 ...
#
# recorded as "teardown or verify-clean failed; stopping the night". Nothing was
# dirty and nothing was unobserved: the arm had never happened (the wrapper
# could not find a trusted CLI), so `unprotect` refused because there was
# NOTHING TO UNPROTECT. "There was nothing to tear down" had collapsed into
# "tearing down failed" -- the same conflation this harness fixed at kickstart
# ("a daemon that does not exist yet is not a daemon that failed to restart")
# and at preflight ("a check that cannot look yet is not a check that failed"),
# reached again the moment the ladder got one rung further.
#
# THE FIX IS NOT A WEAKER STOP-THE-NIGHT RULE, and the predicate below is
# deliberately narrow. `exit 1` still fires on ANY dirt and on ANY check that
# could not observe, because continuing past a dirty teardown wedges the host.
# What changed is which EVIDENCE decides, and that is the seven observations,
# never the verb's exit status on its own:
#
#   ran                          rc=0. The verb did its work.
#   refused-nothing-to-tear-down rc=20 AND a refusal marker AND every one of the
#                                seven checks OBSERVED and OBSERVED CLEAN. The
#                                host is clean because it was looked at, which
#                                is this file's entire doctrine (verify, do not
#                                report) applied to the verb as well as to the
#                                state.
#   refused-but-state-remains    a refusal, with dirt or an unobservable check.
#                                A refusal explains nothing about state we can
#                                still see, or cannot see. STOP THE NIGHT.
#   errored                      any other non-zero status, including rc=20 with
#                                no marker. An uncontrolled exit may have landed
#                                MID-mutation, so post-state that happens to
#                                look clean is not evidence that it is.
#                                STOP THE NIGHT.
TEARDOWN_FAILED=''
if [ "$TEARDOWN_RC" -eq 0 ]; then
  TEARDOWN_VERDICT='ran'
elif [ "$TEARDOWN_RC" -eq "$RAILS_REJECT_STATUS" ] && [ -n "$TEARDOWN_REFUSED" ]; then
  if [ "$DIRTY" -eq 0 ] && [ "$UNOBSERVED" -eq 0 ]; then
    TEARDOWN_VERDICT='refused-nothing-to-tear-down'
  else
    TEARDOWN_VERDICT='refused-but-state-remains'
    TEARDOWN_FAILED='yes'
  fi
else
  TEARDOWN_VERDICT="errored(rc=$TEARDOWN_RC)"
  TEARDOWN_FAILED='yes'
fi

printf 'VERIFY=SUMMARY dirty=%s unobserved=%s teardown=%s teardown_rc=%s clean_markers_rc=%s retire_rc=%s operator_uid=%s\n' \
  "$DIRTY" "$UNOBSERVED" "$TEARDOWN_VERDICT" "$TEARDOWN_RC" "$CLEAN_MARKERS_RC" "$RETIRE_RC" "$OPERATOR_UID"

# UNOBSERVED stops the night exactly as hard as DIRTY. The whole subject of this
# file is that they are different facts, not that one of them is survivable.
if [ "$DIRTY" -ne 0 ] || [ "$UNOBSERVED" -ne 0 ] \
   || [ -n "$TEARDOWN_FAILED" ] || [ "$CLEAN_MARKERS_RC" -ne 0 ] || [ "$RETIRE_RC" -ne 0 ]; then
  exit 1
fi
