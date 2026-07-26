#!/usr/bin/env bash
#
# preflight.sh - every historical defect layer, turned into a permanent check.
#
# Each check below exists because a real drill lost hours to the thing it now
# catches in two seconds. The point of a nightly loop is that layer N+1 gets
# found at 3am; the point of preflight is that layers 1..N never get found
# again.
#
#   D7   the gate daemon was serving a stale dist, so the drill measured code
#        nobody had shipped.
#   D8   a stale exclusive-routing.json marker made a fresh arm look armed.
#   D9   the launchd plist used a PATH-relative node, which resolves under an
#        interactive shell and not under launchd (#986).
#   #987 PyYAML was importable from the operator's shell but not from the
#        interpreter the harness probe actually used.
#   07-22 orphaned registry entries survived a teardown and poisoned the next
#        iteration.
#   0-byte locks: a zero-length audit write lock is UNBREAKABLE by design and
#        bricks a fortress permanently. Never let one into an iteration.
#
# A preflight failure is a FINDING: captured, iteration aborted cleanly, loop
# continues. It is not a crash and it is not silent.
#
# AND A CHECK THAT COULD NOT OBSERVE IS A FAILING CHECK, NEVER A PASSING ONE.
# Round 3 found three checks in this file reporting PASS having measured nothing:
# `orphan-registry` looked at a path the product does not use and read
# "not found" as "not there"; `plist-absolute-node` passed when the plists whose
# whole content it screens were ABSENT; and the marker/lock checks read a
# fortress this process is not allowed to look inside. The registry and the
# fortress are now read through ROOT wrapper verbs, and an absent input set is a
# FAILURE rather than an empty success.
#
# Usage: preflight.sh --run-id <id> --operator-account <a> --build-sha <sha>
#          --agent-account <a> --agent-uid <n> [--base <dir>]
# Exit:  0 all checks passed
#        1 one or more checks failed (details on stdout, machine-readable)

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(CDPATH='' cd -P -- "$HERE/.." && pwd -P)"
REPO="$(CDPATH='' cd -P -- "$ROOT/../.." && pwd -P)"
# shellcheck source=../lib/rails.sh
. "$ROOT/lib/rails.sh"

WRAPPER='/usr/local/sbin/sanctuary-drill-wrapper'

die() {
  printf 'preflight: %s\n' "$*" >&2
  exit 2
}

# ROUND-3 BLOCKER 1. See the long note in run-probe-battery.sh. This file's
# entire output is observations, so every tool it observes through is resolved
# absolutely, once, and PATH is pinned as a belt rather than as the defense.
PATH="$RAILS_SYSTEM_PATH"
export PATH
SUDO="$(rails_require_cmd sudo)" || die 'sudo is not in a root-owned system directory; refusing to preflight through an unresolvable tool'
GREP="$(rails_require_cmd grep)" || die 'grep is not in a root-owned system directory'

RUN_ID=''
OPERATOR=''
BUILD_SHA=''
AGENT=''
AGENT_UID=''
# WHY THIS DRIVER ACCEPTS --base AND THE ROOT WRAPPER DOES NOT.
#
# This script is UNPRIVILEGED. It reads state and reports; it never escalates
# with a path it was handed. The root wrapper takes no base argument at all and
# ignores anything a driver says, so a --base here cannot redirect anything
# that runs as root. It exists so the batteries can drive this file end to end
# in a sandbox, which is how the pf fail-open below is now mutation-proven
# rather than argued about. A structural test asserts the assembled wrapper
# carries no such flag.
BASE="$RAILS_DISPOSABLE_BASE"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --run-id)           RUN_ID="${2:-}"; shift 2 ;;
    --operator-account) OPERATOR="${2:-}"; shift 2 ;;
    --build-sha)        BUILD_SHA="${2:-}"; shift 2 ;;
    --agent-account)    AGENT="${2:-}"; shift 2 ;;
    --agent-uid)        AGENT_UID="${2:-}"; shift 2 ;;
    --base)             BASE="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$RUN_ID" ] || die '--run-id is required'
[ -n "$OPERATOR" ] || die '--operator-account is required'
# The daemon labels and the plist paths this file screens are PER AGENT UID, so
# without one there is nothing to look at and the D7/D9 checks would pass by
# examining an empty set. That is the round-3 class; it is a usage error here.
[ -n "$AGENT_UID" ] || die '--agent-uid is required: every daemon label and plist path this file checks is per confined uid'
[ -n "$AGENT" ] || die '--agent-account is required alongside --agent-uid'

# Rails, in the mandatory form. The path is DERIVED, never supplied: see the
# BLOCKER 1 block in lib/rails.sh.
DERIVED="$(rails_derive_disposable_storage "$BASE" "$OPERATOR" "$RUN_ID")" \
  || die "run id rejected: $RUN_ID"
[ -n "$DERIVED" ] || die 'empty derived storage path'
ANCHOR="$(rails_assert_trusted_dir_chain 'operator anchor' "$BASE/$OPERATOR")" \
  || die "operator anchor is not a trusted chain: $BASE/$OPERATOR"
[ -n "$ANCHOR" ] || die 'empty anchor after rail'
STORAGE="$(rails_assert_disposable_storage "$ANCHOR" "$DERIVED")" \
  || die "storage rail rejected: $DERIVED"
[ -n "$STORAGE" ] || die 'empty storage after rail'

FAILURES=0

check_pass() { printf 'PREFLIGHT=PASS check=%s %s\n' "$1" "${2:-}"; }
check_fail() {
  printf 'PREFLIGHT=FAIL check=%s reason=%s\n' "$1" "$2"
  FAILURES=$((FAILURES + 1))
}

# --- READ INSIDE THE FORTRESS AS ROOT, ONCE -------------------------------
#
# Every check below that looks at a path under $STORAGE reads ABSENCE as GOOD:
# "no stale marker", "no zero-byte lock". A directory this process cannot
# traverse looks exactly like a directory with nothing in it, and it is a live
# concern rather than a hypothetical -- `tightenStoragePermissions` in
# server/src/storage/permissions.ts chmods the whole fortress to 0700 on every
# server start, and the disposable fortress is created ROOT-owned. So from the
# first arm onward an unprivileged read of it returns precisely what "clean"
# looks like.
#
# The previous round's answer was to refuse to conclude, which was honest and
# useless. This is the fix: root reads it, through the wrapper's
# `fortress-state` verb, which walks each path through the same
# `rails_assert_safe_subpath` chokepoint the privileged verbs use and gives
# every entry a NAMED state. There is no state meaning "I did not look".
FORTRESS_RC=0
FORTRESS_OUT="$("$SUDO" -n "$WRAPPER" fortress-state \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" 2>&1)" || FORTRESS_RC=$?

fortress_entry_state() {
  local line
  line="$(printf '%s\n' "$FORTRESS_OUT" | "$GREP" -m1 "^FORTRESS entry=$1 state=" || printf '')"
  if [ -z "$line" ]; then printf ''; return 0; fi
  printf '%s' "${line##*state=}"
}

# --- the SHA the iteration says it is testing -----------------------------
# NOT D7, and no longer labeled as if it were. run-loop.sh defaults
# --build-sha to HEAD of this same checkout, so comparing it to HEAD is a
# tautology that always passes. What this check CAN honestly establish is that
# the checkout is not dirty, i.e. that HEAD actually describes the tree the
# iteration is about to measure. D7 itself is the next check.
if [ -n "$BUILD_SHA" ]; then
  if rails__sys git -C "$REPO" rev-parse HEAD >/dev/null 2>&1; then
    head_sha="$(rails__sys git -C "$REPO" rev-parse HEAD)"
    if [ "$head_sha" != "$BUILD_SHA" ]; then
      check_fail build-sha "checkout is $head_sha, expected $BUILD_SHA"
    elif [ -n "$(rails__sys git -C "$REPO" status --porcelain 2>/dev/null)" ]; then
      check_fail build-sha "checkout is $head_sha but the tree is DIRTY; the sha does not describe what is about to be measured"
    else
      check_pass build-sha "sha=$head_sha tree=clean"
    fi
  else
    check_fail build-sha 'not a git checkout; cannot confirm the dist under test'
  fi
else
  check_fail build-sha '--build-sha not supplied; the iteration could not say what it tested'
fi

# --- D7 PROPER: is the RUNNING daemon serving the dist on disk? ------------
# D7 was "the gate daemon was serving a stale dist". Nothing in the reviewed
# preflight ever looked at a running process. This does: it finds the daemon's
# pid, works out when that process started, and fails if the JavaScript file it
# was launched from has been written SINCE. A daemon older than its own code is
# exactly the D7 shape.
daemon_program_file() {
  # First absolute .js/.cjs/.mjs in the plist's ProgramArguments.
  rails__sys sed -n 's|.*<string>\(/[^<]*\.[cm]\{0,1\}js\)</string>.*|\1|p' "$1" 2>/dev/null | rails__sys head -1
}
daemon_pid() {
  rails__sys launchctl print "system/$1" 2>/dev/null \
    | rails__sys sed -n 's/^[[:space:]]*pid = \([0-9][0-9]*\).*/\1/p' \
    | rails__sys head -1
}
process_start_epoch() {
  local pid="$1" etime secs now
  etime="$(rails__sys ps -o etime= -p "$pid" 2>/dev/null || printf '')"
  if [ -z "$etime" ]; then return 1; fi
  secs="$(rails_etime_to_seconds "$etime")" || return 1
  now="$(rails__now)"
  printf '%s\n' "$(( now - secs ))"
}
file_mtime() {
  rails__sys stat -c '%Y' "$1" 2>/dev/null || rails__sys stat -f '%m' "$1" 2>/dev/null || return 1
}

# The labels and plist paths are PER AGENT UID and come from the pinned product
# constants. The reviewed values (`com.sanctuary.egress-gate{,-peer-resolver}`,
# no uid suffix) matched nothing the product installs, so this loop screened an
# empty set every time.
DAEMON_LABELS="$(rails_product_daemon_labels "$AGENT_UID")" \
  || die "could not compose the product daemon labels for uid $AGENT_UID"
[ -n "$DAEMON_LABELS" ] || die 'empty daemon label list after the rail'

for label in $DAEMON_LABELS; do
  plist="$(rails_product_daemon_plist_path "$label")" \
    || die "could not compose the plist path for $label"
  if [ ! -f "$plist" ]; then
    check_fail "daemon-dist-$label" "no plist at $plist; the daemon is not installed"
    continue
  fi
  prog="$(daemon_program_file "$plist")"
  if [ -z "$prog" ]; then
    check_fail "daemon-dist-$label" "could not read a JavaScript program path out of $plist"
    continue
  fi
  if [ ! -f "$prog" ]; then
    check_fail "daemon-dist-$label" "$plist names $prog, which does not exist"
    continue
  fi
  pid="$(daemon_pid "$label")"
  if [ -z "$pid" ]; then
    check_fail "daemon-dist-$label" "$label is not running; an iteration would measure nothing"
    continue
  fi
  if ! started="$(process_start_epoch "$pid")"; then
    check_fail "daemon-dist-$label" "could not determine when pid $pid started; cannot confirm it is on the current dist"
    continue
  fi
  if ! built="$(file_mtime "$prog")"; then
    check_fail "daemon-dist-$label" "could not stat $prog"
    continue
  fi
  if [ "$built" -gt "$started" ]; then
    check_fail "daemon-dist-$label" "STALE DIST: $prog was written $(( built - started ))s AFTER pid $pid started; kickstart the daemon first (this is D7)"
  else
    check_pass "daemon-dist-$label" "pid=$pid dist=$prog started $(( started - built ))s after its dist was written"
  fi
done

# --- D8: no stale exclusive-routing marker --------------------------------
if [ "$FORTRESS_RC" -ne 0 ]; then
  # ONE failure, not three passes. An unread fortress makes every absence-based
  # check below meaningless, and "absent" is what they call good.
  check_fail fortress-state "could not READ the disposable fortress through the wrapper (rc=$FORTRESS_RC); the stale-marker and zero-byte-lock checks CANNOT be made, and their absence-means-good logic would report PASS having observed nothing"
elif ! printf '%s\n' "$FORTRESS_OUT" | "$GREP" -q '^WRAPPER=FORTRESS-END'; then
  check_fail fortress-state 'the fortress-state verb exited 0 without a FORTRESS-END marker; the read cannot be trusted'
else
  check_pass fortress-state "$STORAGE"

  marker_state="$(fortress_entry_state 'exclusive-routing.json')"
  case "$marker_state" in
    absent) check_pass stale-marker ;;
    '')     check_fail stale-marker 'the fortress read carried no state for exclusive-routing.json; the check could not be made' ;;
    *)      check_fail stale-marker "exclusive-routing.json exists before arm (state=$marker_state)" ;;
  esac

  # --- 0-byte locks brick a fortress permanently --------------------------
  # `present-empty` is the whole finding: a zero-length audit write lock is
  # UNBREAKABLE by design and bricks a fortress permanently. It is a distinct
  # state from `present` for exactly that reason.
  zero_locks=''
  unread_locks=''
  for rel in 'state/_audit/.audit-write.lock' 'state/.provision.lock'; do
    lock_state="$(fortress_entry_state "$rel")"
    case "$lock_state" in
      present-empty) zero_locks="$zero_locks $rel" ;;
      '')            unread_locks="$unread_locks $rel" ;;
      *)             ;;
    esac
  done
  if [ -n "$unread_locks" ]; then
    check_fail zero-byte-lock "the fortress read carried no state for:$unread_locks"
  elif [ -n "$zero_locks" ]; then
    check_fail zero-byte-lock "zero-length lock file(s):$zero_locks"
  else
    check_pass zero-byte-lock
  fi
fi

# --- 07-22: no orphaned registry entry for this storage path --------------
#
# Read AS ROOT through the wrapper. The reviewed check looked at
# `/Library/Application Support/Sanctuary/egress-gate/registry.json`, which
# appears NOWHERE in server/src, and folded "not found" into "not there". The
# product's registry is root-owned 0600 inside a 0700 directory, so correcting
# the path alone would have left this reporting PASS on a `grep` that returned
# "permission denied".
REGISTRY_RC=0
registry_out="$("$SUDO" -n "$WRAPPER" registry-state \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" 2>&1)" || REGISTRY_RC=$?
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
  check_fail orphan-registry "could not READ the pf-anchor registry (rc=$REGISTRY_RC); an unread registry is not an empty registry"
elif [ "$registry_verdict" = 'absent' ]; then
  # ROUND-5 L2. This used to key on `^WRAPPER=REGISTRY-ABSENT`, which the verb
  # emits BEFORE the content region -- and the same output also carries the
  # registry file's own bytes between REGISTRY-BEGIN and REGISTRY-END. A
  # newline in the content followed by that token would short-circuit the
  # dirty check below, which is evaluated AFTER this branch. Not reachable
  # today (root-written JSON has no literal newline), but the verb already
  # emits an unambiguous single-line VERDICT and a verdict is what a verdict
  # should be read from, not a token that can appear inside content.
  check_pass orphan-registry 'no registry file on this host'
elif printf '%s\n' "$registry_out" | "$GREP" -q -F -- "$STORAGE"; then
  check_fail orphan-registry "the registry already references $STORAGE"
elif printf '%s\n' "$registry_out" | "$GREP" -q '^WRAPPER=REGISTRY-END'; then
  check_pass orphan-registry 'read, and it does not reference this fortress'
else
  check_fail orphan-registry 'the registry-state verb exited 0 without a REGISTRY-END marker; the read cannot be trusted'
fi

# --- D9 / #986: launchd plists must name node by ABSOLUTE path ------------
#
# A check whose whole input set is MISSING must not pass. The reviewed version
# screened two plist paths that no product install ever creates, found neither,
# and printed PASS for the D9 layer having read nothing at all.
plist_problem=''
plist_absent=''
plist_seen=0
for label in $DAEMON_LABELS; do
  plist="$(rails_product_daemon_plist_path "$label")" \
    || die "could not compose the plist path for $label"
  if [ ! -f "$plist" ]; then
    plist_absent="$plist_absent $plist"
    continue
  fi
  plist_seen=$((plist_seen + 1))
  # A ProgramArguments entry of a bare `node` resolves under an interactive
  # shell and not under launchd, which is exactly how D9 hid.
  if rails__sys grep -qE '<string>node</string>' "$plist" 2>/dev/null; then
    plist_problem="$plist_problem $plist"
  fi
done
if [ -n "$plist_problem" ]; then
  check_fail plist-absolute-node "PATH-relative node in:$plist_problem"
elif [ -n "$plist_absent" ]; then
  check_fail plist-absolute-node "no plist to screen at:$plist_absent; a check whose whole input set is missing has not passed, it has not run"
elif [ "$plist_seen" -eq 0 ]; then
  check_fail plist-absolute-node 'no daemon plists were screened at all'
else
  check_pass plist-absolute-node "screened $plist_seen plist(s)"
fi

# --- #987: PyYAML must be importable BY THE INTERPRETER THE HARNESS USES --
# Resolve by capability, not existence: the question is never "is a yaml file
# present" but "can the interpreter this harness will actually run import it".
py=''
for cand in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
  if [ -x "$cand" ]; then py="$cand"; break; fi
done
if [ -z "$py" ]; then
  check_fail pyyaml-importable 'no python3 interpreter found'
elif "$py" -c 'import yaml' >/dev/null 2>&1; then
  check_pass pyyaml-importable "interpreter=$py"
else
  check_fail pyyaml-importable "$py cannot import yaml"
fi

# --- agent uid sanity, when one was declared ------------------------------
if [ -n "$AGENT_UID" ]; then
  case "$AGENT_UID" in
    ''|*[!0-9]*) check_fail agent-uid "not numeric: $AGENT_UID" ;;
    0)           check_fail agent-uid 'agent uid is 0' ;;
    *)           check_pass agent-uid "uid=$AGENT_UID" ;;
  esac
fi

printf 'PREFLIGHT=SUMMARY failures=%s storage=%s\n' "$FAILURES" "$STORAGE"
if [ "$FAILURES" -ne 0 ]; then exit 1; fi
