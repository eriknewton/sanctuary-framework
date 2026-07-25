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
# Usage: preflight.sh --run-id <id> --operator-account <a> --build-sha <sha>
#          [--agent-uid <n>] [--base <dir>]
# Exit:  0 all checks passed
#        1 one or more checks failed (details on stdout, machine-readable)

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(CDPATH='' cd -P -- "$HERE/.." && pwd -P)"
REPO="$(CDPATH='' cd -P -- "$ROOT/../.." && pwd -P)"
# shellcheck source=../lib/rails.sh
. "$ROOT/lib/rails.sh"

die() {
  printf 'preflight: %s\n' "$*" >&2
  exit 2
}

RUN_ID=''
OPERATOR=''
BUILD_SHA=''
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
    --agent-uid)        AGENT_UID="${2:-}"; shift 2 ;;
    --base)             BASE="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$RUN_ID" ] || die '--run-id is required'
[ -n "$OPERATOR" ] || die '--operator-account is required'

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

# Read a path under the storage directory through the ONE chokepoint. The
# reviewed build used `[ -f "$STORAGE/state/_audit/.audit-write.lock" ]`, which
# follows a symlinked `state/` exactly the way the root verb did. This runs
# unprivileged, so the consequence was a LYING preflight rather than a root
# primitive, and "verify means OBSERVED state" is the doctrine this file
# exists to enforce.
safe_under_storage() {
  rails_assert_safe_subpath "$STORAGE" "$1" || die "unsafe path under the storage directory: $1"
}

# --- CAN THIS PROCESS SEE INSIDE THE FORTRESS AT ALL? ---------------------
#
# This has to come before every check that reads a path under $STORAGE,
# because those checks read ABSENCE as GOOD. "no stale marker", "no zero-byte
# lock", "no orphaned lock" are all conclusions drawn from a file not being
# there, and a directory this process cannot traverse looks exactly like a
# directory with nothing in it.
#
# It is a live concern, not a hypothetical: `tightenStoragePermissions` in
# server/src/storage/permissions.ts chmods the whole fortress to 0700 on every
# server start, and the disposable fortress is created ROOT-owned (that is
# BLOCKER 1's fix). So from the first arm onward, this unprivileged driver
# cannot read into it, and every absence-based check below would report PASS
# having observed nothing.
#
# Reporting it is the correct behavior for now; reading these paths through a
# wrapper verb is the real fix and is named as an open item in the README.
storage_observable() {
  if [ ! -d "$STORAGE" ]; then return 1; fi
  if [ ! -r "$STORAGE" ]; then return 1; fi
  if [ ! -x "$STORAGE" ]; then return 1; fi
  return 0
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

for label in com.sanctuary.egress-gate com.sanctuary.egress-gate-peer-resolver; do
  plist="/Library/LaunchDaemons/$label.plist"
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
if storage_observable; then
  check_pass storage-observable "$STORAGE"

  # The mandatory call-site form here too. `safe_under_storage` dies inside the
  # command substitution, so without the `||` the abort would depend on
  # `set -e` alone, and relying on `set -e` alone is exactly what this codebase
  # decided not to do after round 1.
  marker="$(safe_under_storage 'exclusive-routing.json')" \
    || die 'safe-subpath rail rejected exclusive-routing.json'
  [ -n "$marker" ] || die 'empty path after the safe-subpath rail'
  if [ -e "$marker" ]; then
    check_fail stale-marker "$marker exists before arm"
  else
    check_pass stale-marker
  fi

  # --- 0-byte locks brick a fortress permanently --------------------------
  zero_locks=''
  for rel in 'state/_audit/.audit-write.lock' 'state/.provision.lock'; do
    lock="$(safe_under_storage "$rel")" || die "safe-subpath rail rejected: $rel"
    [ -n "$lock" ] || die "empty path after the safe-subpath rail: $rel"
    if [ -f "$lock" ] && [ ! -s "$lock" ]; then
      zero_locks="$zero_locks $lock"
    fi
  done
  if [ -n "$zero_locks" ]; then
    check_fail zero-byte-lock "zero-length lock file(s):$zero_locks"
  else
    check_pass zero-byte-lock
  fi
else
  # ONE failure, not three passes. An unreadable fortress makes every
  # absence-based check below meaningless, and "absent" is what they call good.
  check_fail storage-observable "cannot read into $STORAGE as $(rails__sys id -un); the stale-marker and zero-byte-lock checks CANNOT be made, and their absence-means-good logic would report PASS having observed nothing"
fi

# --- 07-22: no orphaned registry entry for this storage path --------------
registry='/Library/Application Support/Sanctuary/egress-gate/registry.json'
if [ -f "$registry" ]; then
  if rails__sys grep -q -- "$STORAGE" "$registry" 2>/dev/null; then
    check_fail orphan-registry "registry already references $STORAGE"
  else
    check_pass orphan-registry
  fi
else
  check_pass orphan-registry 'no registry file yet'
fi

# --- D9 / #986: launchd plists must name node by ABSOLUTE path ------------
plist_problem=''
for plist in \
  /Library/LaunchDaemons/com.sanctuary.egress-gate.plist \
  /Library/LaunchDaemons/com.sanctuary.egress-gate-peer-resolver.plist
do
  if [ -f "$plist" ]; then
    # A ProgramArguments entry of a bare `node` resolves under an interactive
    # shell and not under launchd, which is exactly how D9 hid.
    if rails__sys grep -qE '<string>node</string>' "$plist" 2>/dev/null; then
      plist_problem="$plist_problem $plist"
    fi
  fi
done
if [ -n "$plist_problem" ]; then
  check_fail plist-absolute-node "PATH-relative node in:$plist_problem"
else
  check_pass plist-absolute-node
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
