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
#
# A CHECK THAT COULD NOT OBSERVE IS NOT A CLEAN CHECK. The reviewed build did
# `rules="$(sudo -n pfctl ... || printf '')"` and read the empty string as
# CLEAN, while the README said plainly that the pfctl grant does not exist. On
# the first unattended night that check would have reported CLEAN having
# observed nothing at all. Every observation below now fails CLOSED when it
# cannot be made, and says which one it was.
#
# A failure here is one of the loop's TWO stop-the-night exceptions. Continuing
# past a dirty teardown wedges the host and every later iteration is born
# tainted, so the loop stops rather than compounding state.
#
# Usage: teardown-verify.sh --run-id <id> --operator-account <a>
#          --agent-account <a> --agent-uid <n> --evidence-dir <d> [--base <dir>]
# Exit:  0 torn down and verified clean; 1 dirty (STOP THE NIGHT); 2 usage

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

RUN_ID=''
OPERATOR=''
AGENT=''
AGENT_UID_IN=''
EVIDENCE=''
# See the note in preflight.sh: this driver is unprivileged and the root
# wrapper takes no base argument, so a --base here cannot redirect anything
# that runs as root. It exists so the batteries can drive this file end to end.
BASE="$RAILS_DISPOSABLE_BASE"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id)           RUN_ID="${2:-}"; shift 2 ;;
    --operator-account) OPERATOR="${2:-}"; shift 2 ;;
    --agent-account)    AGENT="${2:-}"; shift 2 ;;
    --agent-uid)        AGENT_UID_IN="${2:-}"; shift 2 ;;
    --evidence-dir)     EVIDENCE="${2:-}"; shift 2 ;;
    --base)             BASE="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$EVIDENCE" ] || die '--evidence-dir is required'
[ -n "$RUN_ID" ] || die '--run-id is required'
mkdir -p "$EVIDENCE"

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

safe_under_storage() {
  rails_assert_safe_subpath "$STORAGE" "$1" || die "unsafe path under the storage directory: $1"
}

# --- tear down ------------------------------------------------------------
TEARDOWN_RC=0
sudo -n "$WRAPPER" unprotect \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" \
  --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
  >> "$LOG" 2>&1 || TEARDOWN_RC=$?
printf 'TEARDOWN rc=%s\n' "$TEARDOWN_RC"

CLEAN_MARKERS_RC=0
sudo -n "$WRAPPER" clean-markers \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" \
  >> "$LOG" 2>&1 || CLEAN_MARKERS_RC=$?
printf 'CLEAN_MARKERS rc=%s\n' "$CLEAN_MARKERS_RC"

# --- verify OBSERVED state, whatever the teardown claimed -----------------
DIRTY=0
clean_pass() { printf 'VERIFY=CLEAN check=%s %s\n' "$1" "${2:-}"; }
clean_fail() {
  printf 'VERIFY=DIRTY check=%s reason=%s\n' "$1" "$2"
  DIRTY=$((DIRTY + 1))
}

registry='/Library/Application Support/Sanctuary/egress-gate/registry.json'
if [ -f "$registry" ] && rails__sys grep -q -- "$STORAGE" "$registry" 2>/dev/null; then
  clean_fail registry "registry still references $STORAGE"
else
  clean_pass registry
fi

# THE FAIL-OPEN THAT WAS. This goes through a wrapper verb, which the NOPASSWD
# grant already covers, so it needs no second grant; and the verb exits nonzero
# when pfctl itself could not run, so "refused", "errored" and "empty anchor"
# are three different answers instead of one empty string.
ANCHOR_RC=0
anchor_out="$(sudo -n "$WRAPPER" pf-anchor-rules \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" 2>&1)" || ANCHOR_RC=$?
printf 'pf anchor read rc=%s:\n%s\n' "$ANCHOR_RC" "$anchor_out" >> "$LOG"
if [ "$ANCHOR_RC" -ne 0 ]; then
  clean_fail pf-anchor "could not READ the pf anchor (rc=$ANCHOR_RC); a check that observed nothing is not a clean verdict"
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

marker="$(safe_under_storage 'exclusive-routing.json')"
if [ -e "$marker" ]; then
  clean_fail marker 'exclusive-routing.json survived teardown'
else
  clean_pass marker
fi

left_locks=''
for rel in 'state/_audit/.audit-write.lock' 'state/.provision.lock'; do
  lock="$(safe_under_storage "$rel")"
  if [ -e "$lock" ]; then left_locks="$left_locks $lock"; fi
done
if [ -n "$left_locks" ]; then
  clean_fail locks "lock file(s) survived teardown:$left_locks"
else
  clean_pass locks
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
agent_code="$(sudo -n -u "$AGENT" curl -sS -o /dev/null -w '%{http_code}' \
  --max-time 15 --connect-timeout 8 https://example.com 2>>"$LOG")" || AGENT_PROBE_RC=$?
printf 'post-teardown agent status=%s probe_rc=%s\n' "${agent_code:-<none>}" "$AGENT_PROBE_RC" >> "$LOG"
if [ "$AGENT_PROBE_RC" -ne 0 ] && [ -z "$agent_code" ]; then
  clean_fail agent-unconfined "could not RUN the as-agent probe (sudo -n -u $AGENT rc=$AGENT_PROBE_RC); the grant for it does not exist, so this check observed nothing"
else
  case "$agent_code" in
    2*|3*) clean_pass agent-unconfined "agent uid $AGENT_UID reaches the network again" ;;
    *)     clean_fail agent-unconfined "agent uid $AGENT_UID still cannot reach the network (code ${agent_code:-000})" ;;
  esac
fi

printf 'VERIFY=SUMMARY dirty=%s teardown_rc=%s clean_markers_rc=%s operator_uid=%s\n' \
  "$DIRTY" "$TEARDOWN_RC" "$CLEAN_MARKERS_RC" "$OPERATOR_UID"

if [ "$DIRTY" -ne 0 ] || [ "$TEARDOWN_RC" -ne 0 ] || [ "$CLEAN_MARKERS_RC" -ne 0 ]; then exit 1; fi
