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
# Usage: preflight.sh --storage <dir> --build-sha <sha> [--agent-uid <n>]
# Exit:  0 all checks passed
#        1 one or more checks failed (details on stdout, machine-readable)

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(CDPATH='' cd -P -- "$HERE/.." && pwd -P)"
# shellcheck source=../lib/rails.sh
. "$ROOT/lib/rails.sh"

die() {
  printf 'preflight: %s\n' "$*" >&2
  exit 2
}

STORAGE_IN=''
BUILD_SHA=''
AGENT_UID=''
OPERATOR_HOME="${HOME:-}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --storage)      STORAGE_IN="${2:-}"; shift 2 ;;
    --build-sha)    BUILD_SHA="${2:-}"; shift 2 ;;
    --agent-uid)    AGENT_UID="${2:-}"; shift 2 ;;
    --home)         OPERATOR_HOME="${2:-}"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "$OPERATOR_HOME" ] || die 'cannot determine the operator home directory'
[ -n "$STORAGE_IN" ] || die '--storage is required'

# Mandatory call-site form. A rejection aborts THIS process, not a subshell.
STORAGE="$(rails_assert_disposable_storage "$OPERATOR_HOME" "$STORAGE_IN")" \
  || die "storage rail rejected: $STORAGE_IN"
[ -n "$STORAGE" ] || die 'empty storage after rail'

FAILURES=0

check_pass() { printf 'PREFLIGHT=PASS check=%s %s\n' "$1" "${2:-}"; }
check_fail() {
  printf 'PREFLIGHT=FAIL check=%s reason=%s\n' "$1" "$2"
  FAILURES=$((FAILURES + 1))
}

# --- D7: the daemons must be running the dist under test ------------------
# The loop records the SHA it believes it is testing; a mismatch means the
# iteration would measure the wrong code, which is worse than not running.
if [ -n "$BUILD_SHA" ]; then
  if git -C "$ROOT/../.." rev-parse HEAD >/dev/null 2>&1; then
    head_sha="$(git -C "$ROOT/../.." rev-parse HEAD)"
    if [ "$head_sha" = "$BUILD_SHA" ]; then
      check_pass build-sha "sha=$head_sha"
    else
      check_fail build-sha "checkout is $head_sha, expected $BUILD_SHA"
    fi
  else
    check_fail build-sha 'not a git checkout; cannot confirm the dist under test'
  fi
else
  check_fail build-sha '--build-sha not supplied; the iteration could not say what it tested'
fi

# --- D8: no stale exclusive-routing marker --------------------------------
marker="$STORAGE/exclusive-routing.json"
if [ -e "$marker" ]; then
  check_fail stale-marker "$marker exists before arm"
else
  check_pass stale-marker
fi

# --- 0-byte locks brick a fortress permanently ----------------------------
zero_locks=''
for lock in \
  "$STORAGE/state/_audit/.audit-write.lock" \
  "$STORAGE/state/.provision.lock"
do
  if [ -f "$lock" ] && [ ! -s "$lock" ]; then
    zero_locks="$zero_locks $lock"
  fi
done
if [ -n "$zero_locks" ]; then
  check_fail zero-byte-lock "zero-length lock file(s):$zero_locks"
else
  check_pass zero-byte-lock
fi

# --- 07-22: no orphaned registry entry for this storage path --------------
registry='/Library/Application Support/Sanctuary/egress-gate/registry.json'
if [ -f "$registry" ]; then
  if grep -q -- "$STORAGE" "$registry" 2>/dev/null; then
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
    if grep -qE '<string>node</string>' "$plist" 2>/dev/null; then
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
