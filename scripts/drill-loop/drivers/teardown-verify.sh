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
# A failure here is one of the loop's TWO stop-the-night exceptions. Continuing
# past a dirty teardown wedges the host and every later iteration is born
# tainted, so the loop stops rather than compounding state.
#
# Usage: teardown-verify.sh --storage <dir> --operator-account <a>
#          --agent-account <a> --agent-uid <n> --evidence-dir <d>
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

STORAGE_IN=''
OPERATOR=''
AGENT=''
AGENT_UID_IN=''
EVIDENCE=''
OPERATOR_HOME="${HOME:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --storage)          STORAGE_IN="${2:-}"; shift 2 ;;
    --operator-account) OPERATOR="${2:-}"; shift 2 ;;
    --agent-account)    AGENT="${2:-}"; shift 2 ;;
    --agent-uid)        AGENT_UID_IN="${2:-}"; shift 2 ;;
    --evidence-dir)     EVIDENCE="${2:-}"; shift 2 ;;
    --home)             OPERATOR_HOME="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$EVIDENCE" ] || die '--evidence-dir is required'
mkdir -p "$EVIDENCE"

STORAGE="$(rails_assert_disposable_storage "$OPERATOR_HOME" "$STORAGE_IN")" \
  || die "storage rail rejected: $STORAGE_IN"
[ -n "$STORAGE" ] || die 'empty storage after rail'
OPERATOR_UID="$(rails_assert_non_root_account operator "$OPERATOR")" \
  || die "operator account rejected: $OPERATOR"
AGENT_UID="$(rails_assert_account_uid agent "$AGENT" "$AGENT_UID_IN")" \
  || die "agent account rejected: $AGENT"

LOG="$EVIDENCE/teardown.log"

# --- tear down ------------------------------------------------------------
TEARDOWN_RC=0
sudo -n "$WRAPPER" unprotect \
  --storage "$STORAGE" --operator-account "$OPERATOR" \
  --agent-account "$AGENT" --agent-uid "$AGENT_UID" \
  >> "$LOG" 2>&1 || TEARDOWN_RC=$?
printf 'TEARDOWN rc=%s\n' "$TEARDOWN_RC"

sudo -n "$WRAPPER" clean-markers \
  --storage "$STORAGE" --operator-account "$OPERATOR" \
  >> "$LOG" 2>&1 || true

# --- verify OBSERVED state, whatever the teardown claimed -----------------
DIRTY=0
clean_pass() { printf 'VERIFY=CLEAN check=%s %s\n' "$1" "${2:-}"; }
clean_fail() {
  printf 'VERIFY=DIRTY check=%s reason=%s\n' "$1" "$2"
  DIRTY=$((DIRTY + 1))
}

registry='/Library/Application Support/Sanctuary/egress-gate/registry.json'
if [ -f "$registry" ] && grep -q -- "$STORAGE" "$registry" 2>/dev/null; then
  clean_fail registry "registry still references $STORAGE"
else
  clean_pass registry
fi

anchor_rules="$(sudo -n pfctl -a com.sanctuary/egress -s rules 2>/dev/null || printf '')"
printf 'pf anchor rules after teardown:\n%s\n' "$anchor_rules" >> "$LOG"
if [ -n "$anchor_rules" ]; then
  clean_fail pf-anchor 'pf anchor still carries rules'
else
  clean_pass pf-anchor
fi

if [ -e "$STORAGE/exclusive-routing.json" ]; then
  clean_fail marker 'exclusive-routing.json survived teardown'
else
  clean_pass marker
fi

left_locks=''
for lock in \
  "$STORAGE/state/_audit/.audit-write.lock" \
  "$STORAGE/state/.provision.lock"
do
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
agent_code="$(sudo -n -u "$AGENT" curl -sS -o /dev/null -w '%{http_code}' \
  --max-time 15 --connect-timeout 8 https://example.com 2>/dev/null || printf '000')"
printf 'post-teardown agent status=%s\n' "$agent_code" >> "$LOG"
case "$agent_code" in
  2*|3*) clean_pass agent-unconfined "agent uid $AGENT_UID reaches the network again" ;;
  *)     clean_fail agent-unconfined "agent uid $AGENT_UID still cannot reach the network (code $agent_code)" ;;
esac

printf 'VERIFY=SUMMARY dirty=%s teardown_rc=%s operator_uid=%s\n' \
  "$DIRTY" "$TEARDOWN_RC" "$OPERATOR_UID"

if [ "$DIRTY" -ne 0 ] || [ "$TEARDOWN_RC" -ne 0 ]; then exit 1; fi
