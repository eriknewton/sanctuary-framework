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
# THREE VERDICTS, NOT TWO (2026-07-25 follow-on to the live Mini1 finding).
# `PREFLIGHT=EXPECTED check=<name> reason=absent-before-arm` is a first-class
# state: it is not a pass, it never clears a check that also has an unexpected
# absence, and it is gated on the arm state OBSERVED by the wrapper -- the same
# one `kickstart-daemons` uses, read off `registry-state`'s verdict line rather
# than recomputed here. See the block on `check_expected` below.
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
EXPECTED=0

check_pass() { printf 'PREFLIGHT=PASS check=%s %s\n' "$1" "${2:-}"; }
check_fail() {
  printf 'PREFLIGHT=FAIL check=%s reason=%s\n' "$1" "$2"
  FAILURES=$((FAILURES + 1))
}

# THE THIRD STATE, and why two were not enough.
#
# 2026-07-25 follow-on to the live Mini1 finding. `kickstart-daemons` (step 0)
# was taught that a per-uid gate daemon which does not exist YET is not a daemon
# that failed to restart. Preflight is step 1 and it screened the SAME per-uid
# labels -- so on the same clean, disarmed host it failed for the same wrong
# reason, one rung higher:
#
#   PREFLIGHT=FAIL check=daemon-dist-ai.sanctuaryprotocol.egress-gate.503 \
#     reason=no plist at /Library/LaunchDaemons/...; the daemon is not installed
#   PREFLIGHT=FAIL check=plist-absolute-node reason=no plist to screen at: ...
#
# The fix is NOT to let an absent plist pass. The round-3 remediation that put
# `no plist to screen` there is right and stays right: a check whose whole input
# set is missing has not passed, it has not run, and the selftest carries that
# case by name. EXPECTED is a third verdict, not a softer PASS:
#
#   * it is never counted as a pass and never printed as one;
#   * it does not clear the check -- if the same check has any unexpected
#     absence, the check FAILS and says so;
#   * it is gated on the SAME observed arm state `kickstart-daemons` uses, read
#     from the wrapper's own `registry-state` verdict rather than recomputed
#     here, so post-arm absence is a hard FAIL and an unreadable registry is a
#     refusal;
#   * and it is visibly distinct in the evidence, so a morning reader can tell
#     "the gate daemons are not up yet, correctly" from "the check ran".
check_expected() {
  printf 'PREFLIGHT=EXPECTED check=%s reason=%s %s\n' "$1" "$2" "${3:-}"
  EXPECTED=$((EXPECTED + 1))
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

# --- READ THE PF-ANCHOR REGISTRY AS ROOT, ONCE, AND TAKE THE WRAPPER'S -----
# --- ARM-STATE ANSWER RATHER THAN COMPUTING A SECOND ONE ------------------
#
# Two consumers, one read: `orphan-registry` further down wants the registry's
# BYTES, and the D7/D9 daemon screens want the one decision derived from them --
# is THIS uid confined right now? Only the second is subtle, and it is the
# decision `kickstart-daemons` already makes one step earlier via
# `wrapper_observe_arm_state`.
#
# So this driver does not answer it. The wrapper's `registry-state` verb prints
# the answer its own single source produced, and this reads it. The alternative
# -- scanning the registry bytes here for `"agent_uid": <n>` -- would be a
# second implementation of one predicate, in a second file, and the two would be
# free to drift on whitespace, on prefix uids, on a pretty-printed registry.
# Round 3 of this harness was lost to exactly that shape (a duplicated matcher
# that let a neutered scan report PASS), so there is one matcher and it lives
# where root already runs.
#
# `--agent-account` rides along because the wrapper pairs the two and refuses a
# uid given without an account; the agent-allowlist rail runs on it either way.
REGISTRY_RC=0
registry_out="$("$SUDO" -n "$WRAPPER" registry-state \
  --run-id "$RUN_ID" --operator-account "$OPERATOR" \
  --agent-account "$AGENT" --agent-uid "$AGENT_UID" 2>&1)" || REGISTRY_RC=$?

# ROUND-5 L2, taken past the token swap. The verb prints the registry file's
# own BYTES between REGISTRY-BEGIN and REGISTRY-END, and its VERDICT after
# them. A `grep` over the combined output therefore reads a machine token out
# of a CONTENT REGION -- which is the defect, not the particular token, and
# just renaming the token would have left it. The verdict is always the LAST
# `WRAPPER=OK verb=registry-state state=` line by construction (content is
# printed before it), so that is what is read, and the arm fields are read off
# that same line for the same reason. Pure shell, no external command: every
# tool a driver's evidence rests on must be absolutely resolved, and a bare
# `tail` here would be the round-3 BLOCKER-1 shape.
registry_verdict=''
registry_arm_state=''
registry_arm_basis=''
while IFS= read -r _rline; do
  case "$_rline" in
    'WRAPPER=OK verb=registry-state state='*)
      _rtail="${_rline#WRAPPER=OK verb=registry-state state=}"
      registry_verdict="${_rtail%% *}"
      registry_arm_state=''
      registry_arm_basis=''
      # Field splitting only; globbing off, because a verdict line carries file
      # paths and a driver must never let one of them expand against the disk.
      set -f
      for _rfield in $_rtail; do
        case "$_rfield" in
          arm_state=*) registry_arm_state="${_rfield#arm_state=}" ;;
          arm_basis=*) registry_arm_basis="${_rfield#arm_basis=}" ;;
        esac
      done
      set +f
      ;;
  esac
done <<REGISTRY_VERDICT_EOF
$registry_out
REGISTRY_VERDICT_EOF

# ARM_STATE is `armed` or `not-armed` ONLY when it was observed. Anything else
# leaves ARM_UNOBSERVED set, and an unobserved arm state can excuse nothing: it
# cannot tell the expected pre-arm absence of a gate daemon from a defect, and
# guessing would have to guess in the direction that makes absence look fine.
ARM_STATE=''
ARM_BASIS=''
ARM_UNOBSERVED=''
if [ "$REGISTRY_RC" -ne 0 ]; then
  ARM_UNOBSERVED="the pf-anchor registry could not be READ through the wrapper (rc=$REGISTRY_RC)"
elif [ -z "$registry_verdict" ]; then
  ARM_UNOBSERVED='the registry-state verb exited 0 without printing a verdict line'
else
  case "$registry_arm_state" in
    armed|not-armed)
      ARM_STATE="$registry_arm_state"
      ARM_BASIS="$registry_arm_basis" ;;
    ''|unqueried)
      ARM_UNOBSERVED="the registry-state verdict carried arm_state=${registry_arm_state:-<absent>} for a call that named uid $AGENT_UID; this wrapper does not answer the arm-state question" ;;
    *)
      ARM_UNOBSERVED="the registry-state verdict carried an unrecognised arm_state '$registry_arm_state'" ;;
  esac
fi

# WHAT AN ABSENT DAEMON MEANS, for one label class. Prints `expected` or
# `unexpected`; refuses (nonzero) when the arm state was never observed, so a
# caller cannot fall through to either answer by accident.
absence_verdict() {
  case "$1" in
    host) printf 'unexpected\n'; return 0 ;;
    gate) ;;
    *) die "unknown daemon label class: $1" ;;
  esac
  if [ -n "$ARM_UNOBSERVED" ]; then return 1; fi
  if [ "$ARM_STATE" = 'armed' ]; then printf 'unexpected\n'; else printf 'expected\n'; fi
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

# --- THE ARM STATE THAT GOVERNS EVERY "IS THIS ABSENCE EXPECTED" BELOW ----
if [ -n "$ARM_UNOBSERVED" ]; then
  check_fail arm-state "$ARM_UNOBSERVED; an UNOBSERVED arm state cannot say whether a missing per-uid gate daemon is the expected pre-arm state or a defect, so no absence below is excused"
else
  check_pass arm-state "agent_uid=$AGENT_UID arm_state=$ARM_STATE arm_basis=$ARM_BASIS"
fi

# --- D7 PROPER: is the RUNNING daemon serving the dist on disk? ------------
# D7 was "the gate daemon was serving a stale dist". Nothing in the reviewed
# preflight ever looked at a running process. This does: it finds the daemon's
# pid, works out when that process started, and fails if the file it was
# launched from has been written SINCE. A daemon older than its own code is
# exactly the D7 shape.
daemon_plist_content() {
  rails__sys cat "$1" 2>/dev/null || printf ''
}
daemon_loaded() {
  rails__sys launchctl print "system/$1" >/dev/null 2>&1
}
# The pid launchd reports for a job, or NOTHING when it has no pid. Prints
# nothing and returns 0 for "launchd does not have this job" -- that is an
# ANSWER, and the caller says what it means.
#
# FOUND BY GIVING THIS FILE A REAL INPUT SET (2026-07-25 follow-on). The
# reviewed reader was `launchctl print | sed | head`. This driver runs under
# `set -o pipefail`, `launchctl print` exits non-zero for a job launchd does not
# have, and `head -1` can SIGPIPE the stage behind it -- so the assignment
# `pid="$(daemon_pid ...)"` returned non-zero and `set -e` killed THE WHOLE
# DRIVER, silently, with no verdict for any check after it. It had never fired
# because the plist was always absent first and the loop `continue`d above it;
# adding the always-installed host daemon to the screen is what reached it. A
# driver that vanishes mid-run is worse than one that fails: run-loop.sh sees a
# nonzero preflight and records a finding whose reason is an empty string.
#
# Pure shell, no pipeline, no external tool: this is an evidence path, and the
# BLOCKER-1 rule is that every tool one rests on is absolutely resolved.
daemon_pid() {
  local printed rc=0 line
  printed="$(rails__sys launchctl print "system/$1" 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then return 0; fi
  while IFS= read -r line; do
    while :; do
      case "$line" in
        ' '*|$'\t'*) line="${line#?}" ;;
        *) break ;;
      esac
    done
    case "$line" in
      'pid = '*)
        line="${line#pid = }"
        line="${line%%[!0-9]*}"
        if [ -n "$line" ]; then printf '%s\n' "$line"; return 0; fi ;;
    esac
  done <<DAEMON_PID_EOF
$printed
DAEMON_PID_EOF
  return 0
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

# THE INPUT SET, IN ITS TWO CLASSES.
#
# The labels and plist paths are PER AGENT UID and come from the pinned product
# constants. The reviewed values (`com.sanctuary.egress-gate{,-peer-resolver}`,
# no uid suffix) matched nothing the product installs, so this loop screened an
# empty set every time.
#
# 2026-07-25 follow-on: it screened an empty set again, for a different reason.
# The per-uid gate labels are the ONLY thing it looked at, and the arm creates
# them -- so before the arm there is nothing on disk to screen and this whole
# section was choosing between an unearned pass and a wrong failure. The
# ALWAYS-INSTALLED host daemon joins the screen so that the pre-arm run is
# actually measuring something rather than being excused for measuring nothing,
# and its absence is never expected.
#
# The signer helper is deliberately NOT in the plist screen: the product ships
# its plist inside the signed app bundle and registers it with `SMAppService`,
# so there is no file at `<LaunchDaemons>/<label>.plist` on a correctly
# installed host and its plist names a bundle-relative `BundleProgram` rather
# than an absolute one. It is screened below by the one signal it does have.
# See the class split in lib/rails.sh.
HOST_PLIST_LABELS="$(rails_product_plist_screenable_host_daemon_labels)" \
  || die 'could not compose the plist-screenable host daemon labels'
[ -n "$HOST_PLIST_LABELS" ] || die 'empty plist-screenable host daemon label list after the rail'
HOST_LAUNCHD_LABELS="$(rails_product_bundle_registered_host_daemon_labels)" \
  || die 'could not compose the bundle-registered host daemon labels'
[ -n "$HOST_LAUNCHD_LABELS" ] || die 'empty bundle-registered host daemon label list after the rail'
GATE_LABELS="$(rails_product_daemon_labels "$AGENT_UID")" \
  || die "could not compose the product daemon labels for uid $AGENT_UID"
[ -n "$GATE_LABELS" ] || die 'empty per-uid daemon label list after the rail'

# One label's D7 screen. $1 is the label, $2 its class (`host` or `gate`), which
# is the only thing that decides what an ABSENCE means.
d7_screen_label() {
  local label="$1" klass="$2" plist prog content pid started built absent
  plist="$(rails_product_daemon_plist_path "$label")" \
    || die "could not compose the plist path for $label"
  if [ ! -f "$plist" ]; then
    if ! absent="$(absence_verdict "$klass")"; then
      check_fail "daemon-dist-$label" "no plist at $plist, and the arm state of uid $AGENT_UID was never observed, so whether that absence is expected CANNOT be decided"
      return 0
    fi
    if [ "$absent" = 'expected' ]; then
      check_expected "daemon-dist-$label" 'absent-before-arm' \
        "arm_state=$ARM_STATE arm_basis=$ARM_BASIS plist=$plist; the arm creates this daemon, so there is nothing to screen yet"
    else
      check_fail "daemon-dist-$label" "no plist at $plist; the daemon is not installed"
    fi
    return 0
  fi
  content="$(daemon_plist_content "$plist")"
  if [ -z "$content" ]; then
    check_fail "daemon-dist-$label" "could not read $plist"
    return 0
  fi
  prog="$(rails_plist_dist_file "$content")"
  if [ -z "$prog" ]; then
    check_fail "daemon-dist-$label" "$plist names no program to stat: neither a Program key nor a ProgramArguments entry"
    return 0
  fi
  if [ ! -f "$prog" ]; then
    check_fail "daemon-dist-$label" "$plist names $prog, which does not exist"
    return 0
  fi
  pid="$(daemon_pid "$label")"
  if [ -z "$pid" ]; then
    check_fail "daemon-dist-$label" "$label is not running; an iteration would measure nothing"
    return 0
  fi
  if ! started="$(process_start_epoch "$pid")"; then
    check_fail "daemon-dist-$label" "could not determine when pid $pid started; cannot confirm it is on the current dist"
    return 0
  fi
  if ! built="$(file_mtime "$prog")"; then
    check_fail "daemon-dist-$label" "could not stat $prog"
    return 0
  fi
  if [ "$built" -gt "$started" ]; then
    check_fail "daemon-dist-$label" "STALE DIST: $prog was written $(( built - started ))s AFTER pid $pid started; kickstart the daemon first (this is D7)"
  else
    check_pass "daemon-dist-$label" "pid=$pid dist=$prog started $(( started - built ))s after its dist was written"
  fi
}

for label in $HOST_PLIST_LABELS; do d7_screen_label "$label" host; done
for label in $GATE_LABELS;       do d7_screen_label "$label" gate; done

# The bundle-registered host daemon, screened by the ONE signal it has. There is
# no plist to stat and no absolute program to compare mtimes against, so this is
# not a D7 staleness check and is not named as one; it is the existence question,
# and the answer is never allowed to be "expected".
for label in $HOST_LAUNCHD_LABELS; do
  if daemon_loaded "$label"; then
    check_pass "daemon-loaded-$label" 'launchd has the job'
  else
    check_fail "daemon-loaded-$label" "launchd does not have system/$label; the product's signed host daemon is not registered, and its absence is never the expected pre-arm state"
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
#
# The read itself, and the parse of its verdict line, happen ONCE near the top
# of this file: the D7/D9 daemon screens need the arm state off the same verdict
# before they run. This is the byte-level half of the same read.
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

# --- D9 / #986: launchd plists must name their program by ABSOLUTE path ----
#
# A check whose whole input set is MISSING must not pass. The reviewed version
# screened two plist paths that no product install ever creates, found neither,
# and printed PASS for the D9 layer having read nothing at all. That case is
# still here, still a FAIL, and the selftest still carries it by name.
#
# What changed is that an absence which is genuinely EXPECTED -- the per-uid
# gate plists on a host this uid is not armed on -- is reported as the third
# state instead of being folded into either verdict, and that the host daemon is
# in the input set so a pre-arm run screens something real rather than being
# excused for screening nothing.
#
# TWO PROPERTIES, not one string:
#
#   1. THE PROGRAM LAUNCHD EXECS MUST BE ABSOLUTE. This is the actual D9
#      property, and it is the one that holds for every plist shape the product
#      renders -- the CLI shim (no extension), the interpreter+script pair, the
#      compiled binary. `<string>node</string>` was only ever the instance of it
#      that #986 happened to find.
#   2. NO BARE `node` ANYWHERE IN THE ARGUMENTS. Kept verbatim from #986,
#      because property 1 does not subsume it: `["/usr/bin/env","node",...]`
#      names an absolute program and STILL resolves its interpreter on a PATH
#      launchd does not provide.
plist_relative=''
plist_bare_node=''
plist_no_program=''
plist_absent_unexpected=''
plist_absent_expected=''
plist_unobserved=''
plist_seen=0
d9_screen_label() {
  local label="$1" klass="$2" plist content prog absent
  plist="$(rails_product_daemon_plist_path "$label")" \
    || die "could not compose the plist path for $label"
  if [ ! -f "$plist" ]; then
    if ! absent="$(absence_verdict "$klass")"; then
      plist_unobserved="$plist_unobserved $plist"
    elif [ "$absent" = 'expected' ]; then
      plist_absent_expected="$plist_absent_expected $plist"
    else
      plist_absent_unexpected="$plist_absent_unexpected $plist"
    fi
    return 0
  fi
  plist_seen=$((plist_seen + 1))
  content="$(daemon_plist_content "$plist")"
  prog="$(rails_plist_program "$content")"
  case "$prog" in
    /*) ;;
    '') plist_no_program="$plist_no_program $plist" ;;
    *)  plist_relative="$plist_relative $plist($prog)" ;;
  esac
  # A ProgramArguments entry of a bare `node` resolves under an interactive
  # shell and not under launchd, which is exactly how D9 hid.
  if rails__sys grep -qE '<string>node</string>' "$plist" 2>/dev/null; then
    plist_bare_node="$plist_bare_node $plist"
  fi
}
for label in $HOST_PLIST_LABELS; do d9_screen_label "$label" host; done
for label in $GATE_LABELS;       do d9_screen_label "$label" gate; done

d9_reason=''
d9_add() { d9_reason="${d9_reason:+$d9_reason; }$1"; }
if [ -n "$plist_relative" ]; then
  d9_add "a program launchd must resolve on PATH in:$plist_relative"
fi
if [ -n "$plist_bare_node" ]; then
  d9_add "PATH-relative node in:$plist_bare_node"
fi
if [ -n "$plist_no_program" ]; then
  d9_add "no program named at all in:$plist_no_program"
fi
if [ -n "$plist_unobserved" ]; then
  d9_add "no plist to screen at:$plist_unobserved, and the arm state was never observed so the absence cannot be excused"
fi
if [ -n "$plist_absent_unexpected" ]; then
  d9_add "no plist to screen at:$plist_absent_unexpected; a check whose whole input set is missing has not passed, it has not run"
fi
if [ -z "$d9_reason" ] && [ "$plist_seen" -eq 0 ]; then
  d9_add 'no daemon plists were screened at all'
fi
# The expected absences are reported whichever way the check went: they are the
# reason the screened set is smaller than the label set, and a reader who cannot
# see them cannot tell a short screen from a silent one.
if [ -n "$plist_absent_expected" ]; then
  check_expected plist-absolute-node 'absent-before-arm' \
    "arm_state=$ARM_STATE arm_basis=$ARM_BASIS plists:$plist_absent_expected"
fi
if [ -n "$d9_reason" ]; then
  check_fail plist-absolute-node "$d9_reason"
else
  check_pass plist-absolute-node "screened $plist_seen plist(s)"
fi

# --- #987: PyYAML must be importable BY AN INTERPRETER THE HARNESS CAN USE --
#
# THE SAME DEFECT CLASS AS EVERYTHING ABOVE, AND THE THIRD COPY OF THIS EXACT
# BUG. The reviewed check read:
#
#   for cand in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
#     if [ -x "$cand" ]; then py="$cand"; break; fi     # first EXISTING
#   done
#   ... "$py" -c 'import yaml'                          # then test only that one
#
# FIRST-EXISTING IS NOT FIRST-CAPABLE. `/usr/bin/python3` is on every macOS box,
# so it always won the loop; on the drill host it is also the one WITHOUT
# PyYAML, while `/opt/homebrew/bin/python3` has it. The 2026-07-25 live run
# therefore reported
#
#   PREFLIGHT=FAIL check=pyyaml-importable reason=/usr/bin/python3 cannot import yaml
#
# about a host where PyYAML was installed and importable, which is this file's
# governing defect once more: the verdict was computed from something other than
# the thing it claims to measure -- existence standing in for capability. The
# header comment even said "resolve by capability, not existence" while the code
# below it did the opposite. The product hit this twice (#987, and a 2026-07-22
# backout) before landing the capability walk.
#
# WHY THIS IS A SEPARATE IMPLEMENTATION RATHER THAN A CALL INTO THE PRODUCT.
# The product's chokepoint is `probePyYamlCandidates()` /
# `hermesParityPythonCandidates()` in server/src/wrap/hermes-yaml-parse-parity.ts,
# surfaced as the `hermes config parser` check in `sanctuary doctor`, and asking
# IT would be the better shape in almost any other file. Not here, for two
# reasons that are specific to preflight:
#
#   1. PREFLIGHT SCREENS THE DIST. Its whole job is to establish that the host
#      is fit before an iteration measures the build under test; the check
#      immediately above it fails when the checkout is dirty. Answering a
#      preflight question by RUNNING that same build makes preflight's verdict
#      depend on the artifact it is screening, so a broken dist would report
#      itself as "PyYAML is missing" -- the identical substitution this block
#      exists to remove.
#   2. THE CLI IS NOT A TOOL THIS FILE MAY REST ON. Every tool a driver's
#      evidence goes through is resolved absolutely out of a root-owned system
#      directory (BLOCKER 1); the built CLI lives in a checkout the operator can
#      write.
#
# So the walk is mirrored here, and the DRIFT is closed the way every other
# product identifier in this harness is: the candidate list is not re-spelled,
# it comes from `RAILS_PRODUCT_PYTHON3_CANDIDATES`, which product-identifiers.
# test.ts pins to the product's own `SYSTEM_PYTHON3_CANDIDATES`. If the product
# adds an interpreter, that test goes red rather than this file quietly probing
# a shorter list.
#
# The candidates are absolute and code-controlled, so they are executed by path
# rather than through `rails__sys` (which resolves by NAME within the system bin
# dirs). `-E` mirrors the product: PYTHONPATH/PYTHONHOME are ignored so a
# planted `yaml` module cannot make a bare interpreter look capable. `-I`/`-s`
# are deliberately NOT used, again mirroring the product, because they would
# also drop user site-packages where a `pip install --user` PyYAML legitimately
# lives.
PYYAML_PROBE_PROGRAM='import sys
try:
    import yaml
except ImportError:
    sys.exit(20)
sys.exit(0)'

# One candidate: `usable`, `no-pyyaml`, `absent` or `unrunnable`. Exit 20 is the
# import failure specifically, mirroring the product`s IMPORT_MISSING, so an
# interpreter that dies for some OTHER reason is not filed as "no PyYAML".
pyyaml_probe_candidate() {
  local cand="$1" rc=0
  if [ ! -e "$cand" ]; then printf 'absent\n'; return 0; fi
  if [ ! -x "$cand" ]; then printf 'unrunnable\n'; return 0; fi
  "$cand" -E -c "$PYYAML_PROBE_PROGRAM" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0)  printf 'usable\n' ;;
    20) printf 'no-pyyaml\n' ;;
    *)  printf 'unrunnable(rc=%s)\n' "$rc" ;;
  esac
}

PY_CANDIDATES="$(rails_product_python3_candidates)" \
  || die 'could not compose the product python3 candidate list'
[ -n "$PY_CANDIDATES" ] || die 'empty python3 candidate list after the rail'

py=''
py_outcomes=''
for cand in $PY_CANDIDATES; do
  cand_state="$(pyyaml_probe_candidate "$cand")"
  py_outcomes="$py_outcomes $cand=$cand_state"
  # FIRST CAPABLE WINS, and the walk stops there: a later candidate's state is
  # not evidence about a host whose question has already been answered yes.
  if [ "$cand_state" = 'usable' ] && [ -z "$py" ]; then py="$cand"; break; fi
done
if [ -n "$py" ]; then
  check_pass pyyaml-importable "interpreter=$py probed:$py_outcomes"
else
  # A real blocker, still. The drill needs SOME interpreter that can import
  # yaml; what changed is that this now says PyYAML is missing from every
  # interpreter we are allowed to use, and names what each one did, instead of
  # blaming the first one that happened to exist.
  check_fail pyyaml-importable "no python3 candidate can import yaml; probed:$py_outcomes"
fi

# --- agent uid sanity, when one was declared ------------------------------
if [ -n "$AGENT_UID" ]; then
  case "$AGENT_UID" in
    ''|*[!0-9]*) check_fail agent-uid "not numeric: $AGENT_UID" ;;
    0)           check_fail agent-uid 'agent uid is 0' ;;
    *)           check_pass agent-uid "uid=$AGENT_UID" ;;
  esac
fi

# `expected` is reported alongside `failures` and never folded into it. A run
# with expected=2 failures=0 is a clean pre-arm host; a run with expected=0 on
# the same host would mean the gate plists appeared without an arm, which is a
# different morning.
printf 'PREFLIGHT=SUMMARY failures=%s expected=%s storage=%s\n' "$FAILURES" "$EXPECTED" "$STORAGE"
if [ "$FAILURES" -ne 0 ]; then exit 1; fi
