#!/usr/bin/env bash
#
# selftest.sh - re-prove the safety rails IN PLACE, with no vitest and no node.
#
# The same battery runs in CI as server/test/drill-loop/rails.test.ts. This
# standalone copy exists because the machine that actually matters is the drill
# host, and the drill host does not run the TypeScript suite. Run this there
# before any nightly loop, and after any wrapper reinstall.
#
#   scripts/drill-loop/selftest.sh
#
# Every case asserts BOTH halves of a rejection: a nonzero exit AND no ACCEPT
# token anywhere in the output. See lib/probe.sh for why both halves are load
# bearing.
#
# This script touches nothing outside a mktemp sandbox. It never reads or
# writes a real fortress: the `~/.sanctuary` denylist case is reproduced
# against a FAKE `.sanctuary` inside the sandbox, which exercises exactly the
# same code path with none of the risk.
#
# DECLARED `set -e` EXCEPTIONS. The first build's self-report claimed there
# were none anywhere in the harness, and the review refuted it. There are four,
# all in this file, all of the same shape: a command is EXPECTED to fail and
# its status is the thing being measured, so `set -e` is suspended for exactly
# the length of the capture and restored immediately.
#
#   expect_reject()  captures the status of a command that must fail
#   expect_accept()  captures the status of a command that must succeed
#   the concurrent stale-lock case, which waits on two background jobs
#   the driver cases at the bottom, which run a driver expected to exit 1
#
# No rail is called inside any of them.

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROBE="$HERE/lib/probe.sh"

PASS=0
SKIPPED=0
FAIL=0
SANDBOX=''

cleanup() {
  if [ -n "$SANDBOX" ] && [ -d "$SANDBOX" ]; then rm -rf "$SANDBOX"; fi
}
trap cleanup EXIT

note() { printf '  %s\n' "$*"; }

# expect_reject <name> <expected-reason-substring> -- <command...>
#
# The reason is checked, not just the status. Drill doctrine: a deny for the
# WRONG reason is a failure, not a pass. Several of these cases have more than
# one thing wrong with them, and a rail that rejected the symlink case because
# of a typo in its prefix check would look identical to one that rejected it
# because it refuses to follow symlinks.
expect_reject() {
  local name="$1" reason="$2"; shift 2
  if [ "${1:-}" = '--' ]; then shift; fi
  local out status
  set +e
  out="$("$@" 2>&1)"
  status=$?
  set -e
  if [ "$status" -eq 0 ]; then
    printf 'FAIL  %s: expected a nonzero exit, got 0\n' "$name"
    note "output: $out"
    FAIL=$((FAIL + 1))
    return 0
  fi
  case "$out" in
    *ACCEPT*)
      printf 'FAIL  %s: rejected with status %s but still printed an ACCEPT token\n' "$name" "$status"
      note "output: $out"
      FAIL=$((FAIL + 1))
      return 0
      ;;
  esac
  case "$out" in
    *"$reason"*) ;;
    *)
      printf 'FAIL  %s: rejected, but not for the expected reason (%s)\n' "$name" "$reason"
      note "output: $out"
      FAIL=$((FAIL + 1))
      return 0
      ;;
  esac
  printf 'ok    %s (exit %s)\n' "$name" "$status"
  PASS=$((PASS + 1))
}

# expect_accept <name> <expected-substring> -- <command...>
expect_accept() {
  local name="$1" want="$2"; shift 2
  if [ "${1:-}" = '--' ]; then shift; fi
  local out status
  set +e
  out="$("$@" 2>&1)"
  status=$?
  set -e
  if [ "$status" -ne 0 ]; then
    printf 'FAIL  %s: expected exit 0, got %s\n' "$name" "$status"
    note "output: $out"
    FAIL=$((FAIL + 1))
    return 0
  fi
  case "$out" in
    *"$want"*) ;;
    *)
      printf 'FAIL  %s: output did not contain %s\n' "$name" "$want"
      note "output: $out"
      FAIL=$((FAIL + 1))
      return 0
      ;;
  esac
  printf 'ok    %s\n' "$name"
  PASS=$((PASS + 1))
}

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/sanctuary-drill-selftest.XXXXXX")"
# CANONICALIZE. On a Mac `$TMPDIR` is under /var/folders, and /var is a symlink
# into /private, so an uncanonicalized sandbox path is not equal to its own
# resolution. The rails deliberately require canonical input (a rail that
# quietly accepted "some path that resolves to the right place" would be
# accepting exactly the shape the symlink exploits used), so the fixture has to
# be canonical too.
SANDBOX="$(CDPATH='' cd -P -- "$SANDBOX" && pwd -P)"
ME="$(id -un)"
# The disposable BASE and the per-operator ANCHOR, standing in for the
# root-owned `/private/var/sanctuary-drill` the shipped wrapper compiles in.
BASE="$SANDBOX/base"
ANCHOR="$BASE/$ME"
mkdir -p "$ANCHOR"
# A stand-in for a real default fortress. The denylist and the symlink cases
# both aim at THIS, never at a real one.
mkdir -p "$ANCHOR/.sanctuary"
mkdir -p "$ANCHOR/.sanctuary-loop-good"
mkdir -p "$SANDBOX/outside/.sanctuary-loop-outside"
ln -s "$ANCHOR/.sanctuary" "$ANCHOR/.sanctuary-loop-evil"
ln -s "$BASE" "$SANDBOX/base-link"
# The old name, kept as an alias so the storage cases below read the same way.
HOME_DIR="$ANCHOR"

printf '== storage rail ==\n'
expect_reject 'empty storage path' 'empty storage path' \
  -- "$PROBE" storage "$HOME_DIR" ''
expect_reject 'missing storage argument' 'expected 2 args' \
  -- "$PROBE" storage "$HOME_DIR"
expect_reject 'the default fortress itself' 'protected fortress' \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR/.sanctuary"
expect_reject 'symlink to the fortress' 'final component is a symlink' \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR/.sanctuary-loop-evil"
expect_reject 'traversal back to fortress' 'relative component' \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR/.sanctuary-loop-x/../.sanctuary"
expect_reject 'traversal with trailing slash' 'relative component' \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR/.sanctuary-loop-x/../"
expect_reject 'outside the anchor, valid basename' 'is not the approved anchor' \
  -- "$PROBE" storage "$HOME_DIR" "$SANDBOX/outside/.sanctuary-loop-outside"
expect_reject 'relative path' 'not an absolute path' \
  -- "$PROBE" storage "$HOME_DIR" '.sanctuary-loop-rel'
expect_reject 'no disposable prefix' 'not a disposable loop fortress' \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR/scratch"
expect_reject 'bare prefix, no stamp' 'not a disposable loop fortress' \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR/.sanctuary-loop-"
expect_accept 'valid disposable fortress' 'PROBE=ACCEPT' \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR/.sanctuary-loop-good"
expect_accept 'valid, not yet created' 'PROBE=ACCEPT' \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR/.sanctuary-loop-fresh-1"
expect_accept 'normalizes slashes' ".sanctuary-loop-good" \
  -- "$PROBE" storage "$HOME_DIR" "$HOME_DIR//.sanctuary-loop-good/"

printf '== run-id rail (the caller no longer supplies a path at all) ==\n'
expect_accept 'plain run id' 'PROBE=ACCEPT'          -- "$PROBE" run-id '20260725t0230-1'
# LOWERCASE ONLY. `A` and `a` were two accepted run ids and ONE directory entry
# on the case-insensitive APFS volume the drill hosts run (round-3 MED, both
# lenses). Rejected rather than folded: the evidence must show the exact id the
# caller supplied.
expect_reject 'UPPERCASE run id (case-insensitive APFS alias)' 'disallowed characters' \
  -- "$PROBE" run-id '20260725T0230-1'
expect_reject 'a single uppercase letter aliases its lowercase twin' 'disallowed characters' \
  -- "$PROBE" run-id 'A'
expect_accept 'its lowercase twin is accepted' 'PROBE=ACCEPT' -- "$PROBE" run-id 'a'
expect_reject 'empty run id' 'empty run id'          -- "$PROBE" run-id ''
expect_reject 'run id with a slash' 'disallowed characters' -- "$PROBE" run-id 'a/b'
expect_reject 'run id traversal' 'disallowed characters'    -- "$PROBE" run-id '../evil'
expect_reject 'run id leading dot' 'must start with a lowercase letter or a digit' -- "$PROBE" run-id '.hidden'
expect_reject 'option-shaped run id' 'must start with a lowercase letter or a digit' -- "$PROBE" run-id '-rf'
expect_reject 'over-long run id' 'longer than' \
  -- "$PROBE" run-id 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
expect_accept 'derivation composes the path' ".sanctuary-loop-x1" \
  -- "$PROBE" derive "$BASE" "$ME" 'x1'
expect_reject 'derivation refuses a relative base' 'not an absolute path' \
  -- "$PROBE" derive 'relative/base' "$ME" 'x1'
expect_reject 'derivation refuses root as operator' 'disallowed characters' \
  -- "$PROBE" derive "$BASE" 'ro ot' 'x1'

printf '== the aggregation rule: a SKIP can never become a PASS ==\n'
#
# ROUND-3, Codex finding 2. The battery said `N3 SKIP`, left its failure count
# at zero, exited 0, and run-loop.sh wrote `"result":"PASS"` into
# FINDINGS.jsonl. Both signals must agree before this says PASS.
SUM_OK='PROBE=SUMMARY failures=0 skipped_count=0 verified=yes declared=a,b ran=a,b skipped='
SUM_SKIP='PROBE=SUMMARY failures=0 skipped_count=1 verified=no declared=a,b ran=a skipped=b'
SUM_LIAR='PROBE=SUMMARY failures=0 skipped_count=1 verified=yes declared=a,b ran=a skipped=b'
expect_accept 'a clean battery is a PASS' 'probe-result=PASS' \
  -- "$PROBE" probe-result 0 "$SUM_OK"
expect_accept 'a skipped probe is UNVERIFIED, never PASS' 'probe-result=UNVERIFIED' \
  -- "$PROBE" probe-result 3 "$SUM_SKIP"
expect_accept 'a skipped probe that somehow exited 0 is STILL not a PASS' 'probe-result=UNVERIFIED' \
  -- "$PROBE" probe-result 0 "$SUM_SKIP"
expect_accept 'a summary claiming verified=yes while NAMING skips is UNVERIFIED' 'probe-result=UNVERIFIED' \
  -- "$PROBE" probe-result 0 "$SUM_LIAR"
expect_accept 'a missing summary line is UNVERIFIED, never PASS' 'probe-result=UNVERIFIED' \
  -- "$PROBE" probe-result 0 'the probe battery produced no SUMMARY line'
expect_accept 'a genuinely failed battery is a FAIL' 'probe-result=FAIL' \
  -- "$PROBE" probe-result 1 "$SUM_OK"
expect_reject 'a non-numeric status is refused' 'status is not numeric' \
  -- "$PROBE" probe-result 'zero' "$SUM_OK"
# The REAL summary shape the battery emits now carries `defects=`, and
# `skipped=` must stay the LAST field: `rails_probe_result` reads a non-empty
# tail after `skipped=` as "this summary names skipped probes", so a field
# appended after it would make every battery read as unverified forever.
SUM_REAL='PROBE=SUMMARY failures=0 defects=0 skipped_count=0 verified=yes declared=P1,N1 ran=P1,N1 skipped='
SUM_DEFECT='PROBE=SUMMARY failures=0 defects=1 skipped_count=1 verified=no declared=P1,N1 ran=P1 skipped=N1'
expect_accept 'the real summary shape still folds to PASS' 'probe-result=PASS' \
  -- "$PROBE" probe-result 0 "$SUM_REAL"
expect_accept 'a summary reporting a HARNESS DEFECT is never a PASS' 'probe-result=UNVERIFIED' \
  -- "$PROBE" probe-result 4 "$SUM_DEFECT"

printf '== round 6: a verdict may not outrun its observation (the pure half) ==\n'
#
# Six review rounds, six "different" defects, ONE class: every verdict was
# computed from something other than the thing it claimed to have measured.
# These are the pure, exhaustively drivable rails that make the class
# unrepresentable; the ledger that uses them is driven end to end further down.

# --- the port a probe is allowed to aim at -------------------------------
expect_accept 'an ordinary ephemeral port' 'tcp-port=49152'  -- "$PROBE" tcp-port 49152
expect_accept 'the lowest legal port' 'tcp-port=1'           -- "$PROBE" tcp-port 1
expect_accept 'the highest legal port' 'tcp-port=65535'      -- "$PROBE" tcp-port 65535
expect_reject 'port zero' 'leading zero'                     -- "$PROBE" tcp-port 0
# `08` is not octal-8, it is an INVALID octal literal, and `010` is 8. A token
# that READS as one port would be a different port to the shell.
expect_reject 'a leading-zero port' 'leading zero'           -- "$PROBE" tcp-port 08
expect_reject 'a port above the range' 'out of range'        -- "$PROBE" tcp-port 65536
expect_reject 'an empty port' 'empty tcp port'               -- "$PROBE" tcp-port ''
expect_reject 'a non-numeric port' 'not a decimal integer'   -- "$PROBE" tcp-port 'http'
expect_reject 'a port with a trailing newline injection' 'not a decimal integer' \
  -- "$PROBE" tcp-port '4711 evil'

# --- reading the gate port out of the daemon's own runtime state ---------
GATE_STATE_JSON='{"agent_uid":502,"gate_port":49317,"generation_id":7,"pid":881,"pid_start":"881-1"}'
expect_accept 'the real runtime-state shape yields the port' 'json-number=49317' \
  -- "$PROBE" json-number "$GATE_STATE_JSON" gate_port
expect_accept 'and the generation' 'json-number=7' \
  -- "$PROBE" json-number "$GATE_STATE_JSON" generation_id
expect_reject 'an absent field is refused, never defaulted' 'carries no "listen_port" field' \
  -- "$PROBE" json-number "$GATE_STATE_JSON" listen_port
# THE REASON THIS IS NOT A REGEX SCAN. A nested or duplicated key is exactly
# how "read a value from somewhere other than what you claimed" gets in, so a
# field that appears twice is REFUSED rather than resolved by position.
expect_reject 'a NESTED gate_port cannot be mistaken for the real one' 'more than once' \
  -- "$PROBE" json-number '{"gate_port":1,"stale":{"gate_port":2}}' gate_port
expect_reject 'a duplicated field is refused' 'more than once' \
  -- "$PROBE" json-number '{"gate_port":1,"gate_port":2}' gate_port
expect_reject 'a quoted port is not a bare number' 'not a bare decimal number' \
  -- "$PROBE" json-number '{"gate_port":"49317"}' gate_port
expect_reject 'a null port is not a number' 'not a bare decimal number' \
  -- "$PROBE" json-number '{"gate_port":null}' gate_port
expect_reject 'an empty document carries nothing' 'carries no "gate_port" field' \
  -- "$PROBE" json-number '' gate_port
# A `*` inside the document must not be expanded against the working directory
# when the text is word-split. Globbing off is what makes the parse a parse.
expect_accept 'a glob character in the document is inert' 'json-number=42' \
  -- "$PROBE" json-number '{"note":"*","gate_port":42}' gate_port

expect_accept 'the gate runtime state path is composed from the product constant' \
  'gate-runtime-state-path=/var/db/sanctuary/gate-runtime/502/state.json' \
  -- "$PROBE" gate-runtime-state-path 502
expect_reject 'no runtime state path for uid 0' 'agent uid 0' \
  -- "$PROBE" gate-runtime-state-path 0

# --- a claim that NAMES a mechanism must have exercised it ---------------
#
# ROUND-5 B1 in its most compressed form. `P1` printed
# `RESULT=PASS "allowed endpoints reachable through the gate"` for a bare
# `curl` that had no `--proxy` and could not have had one. The sentence is a
# claim about a MECHANISM, and a mechanism claim is now checkable.
expect_accept 'a through-gate claim is recognised as a mechanism claim' 'claim-mechanisms=gate-channel' \
  -- "$PROBE" claim-mechanisms 'allowed endpoints reachable through the gate'
expect_accept 'so is the hyphenated form' 'claim-mechanisms=gate-channel' \
  -- "$PROBE" claim-mechanisms '2 of 6 through-gate attempts did not succeed'
expect_accept 'CASE does not get a text out of the check' 'claim-mechanisms=gate-channel' \
  -- "$PROBE" claim-mechanisms 'Reachable THROUGH THE GATE'
expect_accept 'a denial-reason claim names the gate-log mechanism' 'claim-mechanisms=gate-log' \
  -- "$PROBE" claim-mechanisms 'denied by the allowlist in the current log window'
expect_accept 'peer_uid_mismatch is a gate-log claim' 'claim-mechanisms=gate-log' \
  -- "$PROBE" claim-mechanisms 'denied with peer_uid_mismatch'
expect_accept 'a text that claims BOTH names both' 'claim-mechanisms=gate-channel,gate-log' \
  -- "$PROBE" claim-mechanisms 'reachable through the gate, denied by the allowlist'
expect_accept 'a text that claims no mechanism claims nothing' 'claim-mechanisms=' \
  -- "$PROBE" claim-mechanisms 'operator uid 501 is unconfined'

expect_accept 'a through-gate claim backed by a through-gate basis is allowed' 'claim-supported=yes' \
  -- "$PROBE" claim-supported 'reachable through the gate' 'gate-channel'
expect_reject 'a through-gate claim on a DIRECT basis is refused' "claims the 'gate-channel' mechanism" \
  -- "$PROBE" claim-supported 'reachable through the gate' 'direct-only'
expect_reject 'a through-gate claim with NO basis mechanism is refused' "claims the 'gate-channel' mechanism" \
  -- "$PROBE" claim-supported 'reachable through the gate' ''
expect_reject 'an allowlist-reason claim without a gate-log observation is refused' "claims the 'gate-log' mechanism" \
  -- "$PROBE" claim-supported 'denied by the allowlist' 'gate-channel'
expect_accept 'a claim that names nothing needs nothing' 'claim-supported=yes' \
  -- "$PROBE" claim-supported 'operator uid 501 is unconfined' ''
expect_reject 'a text claiming BOTH mechanisms needs both' "claims the 'gate-log' mechanism" \
  -- "$PROBE" claim-supported 'reachable through the gate, denied by the allowlist' 'gate-channel'
expect_accept 'and passes when both are present' 'claim-supported=yes' \
  -- "$PROBE" claim-supported 'reachable through the gate, denied by the allowlist' 'gate-channel gate-log'

printf '== trusted-chain rail (the root-owned base) ==\n'
expect_accept 'a real system directory' 'PROBE=ACCEPT'  -- "$PROBE" trusted-chain base /usr
expect_accept 'the sandbox base' 'PROBE=ACCEPT'         -- "$PROBE" trusted-chain base "$BASE"
expect_reject 'a symlinked base' 'is a symlink' \
  -- "$PROBE" trusted-chain base "$SANDBOX/base-link"
expect_reject 'a base that does not exist' 'does not resolve' \
  -- "$PROBE" trusted-chain base "$SANDBOX/no-such-base"
# The PURE per-component predicate: the security logic, driven exhaustively
# without root and without a fixture filesystem.
expect_accept 'component owned by root' 'PROBE=ACCEPT' \
  -- "$PROBE" trusted-component /some/dir 0 755 501
expect_accept 'component owned by me' 'PROBE=ACCEPT' \
  -- "$PROBE" trusted-component /some/dir 501 700 501
expect_reject 'component owned by a THIRD party' 'neither root nor this process' \
  -- "$PROBE" trusted-component /some/dir 999 755 501
expect_reject 'group-writable component' 'group- or world-writable' \
  -- "$PROBE" trusted-component /some/dir 0 775 501
expect_reject 'world-writable component' 'group- or world-writable' \
  -- "$PROBE" trusted-component /some/dir 0 777 501
expect_accept 'world-writable but STICKY (this is /tmp)' 'PROBE=ACCEPT' \
  -- "$PROBE" trusted-component /tmp 0 1777 501

# ...AND THE MODE READER THE CARVE-OUT IS DECIDED ON (round-3 L2).
#
# The predicate above is fed by `rails__stat_mode`, whose BSD branch used to
# read `%Lp` -- which DROPS the high bits. Measured on this Mac, `/private/tmp`
# reports `%Lp=777` for a directory whose real mode is `1777`, so on the ONLY
# platform this harness will ever run on, `8#$mode & 8#1000` was always zero and
# the sticky carve-out documented as "what makes /tmp safe as a path component"
# could never fire. The direction was fail-closed, so it was not a hole; it was
# a security predicate that behaved differently on macOS and Linux while being
# documented as if it worked on both. These two cases are what make the reader
# and the predicate agree.
STICKYDIR="$SANDBOX/sticky"
mkdir -p "$STICKYDIR"
chmod 1777 "$STICKYDIR"
expect_accept 'the mode reader SEES the sticky bit' 'mode=1777' \
  -- "$PROBE" stat-mode "$STICKYDIR"
expect_accept 'a sticky world-writable component is accepted end to end' 'PROBE=ACCEPT' \
  -- "$PROBE" trusted-chain base "$STICKYDIR"
chmod 0777 "$STICKYDIR"
expect_reject 'the SAME component without the sticky bit is refused' 'without the sticky bit' \
  -- "$PROBE" trusted-chain base "$STICKYDIR"
chmod 0755 "$STICKYDIR"

printf '== safe-subpath rail (the ONE resolution chokepoint) ==\n'
SUB="$ANCHOR/.sanctuary-loop-good"
mkdir -p "$SUB/state/_audit"
printf 'lock\n' > "$SUB/state/_audit/.audit-write.lock"
expect_accept 'a genuine nested target' 'PROBE=ACCEPT' \
  -- "$PROBE" safe-subpath "$SUB" 'state/_audit/.audit-write.lock'
expect_accept 'a target that does not exist yet' 'PROBE=ACCEPT' \
  -- "$PROBE" safe-subpath "$SUB" 'exclusive-routing.json'
expect_reject 'traversal out of the root' 'relative or empty component' \
  -- "$PROBE" safe-subpath "$SUB" '../../.sanctuary/state'
expect_reject 'an absolute relative-path' 'must not be absolute' \
  -- "$PROBE" safe-subpath "$SUB" '/etc/passwd'
# THE EXECUTED EXPLOIT, at rail level: an INTERMEDIATE component is a symlink.
rm -rf "$SUB/state"
ln -s "$ANCHOR/.sanctuary" "$SUB/state"
expect_reject 'symlinked INTERMEDIATE component' 'is a symlink' \
  -- "$PROBE" safe-subpath "$SUB" 'state/_audit/.audit-write.lock'
rm -f "$SUB/state"
mkdir -p "$SUB/state/_audit"
ln -s "$ANCHOR/.sanctuary" "$SUB/state/_audit/.audit-write.lock"
expect_reject 'symlinked FINAL component' 'is a symlink' \
  -- "$PROBE" safe-subpath "$SUB" 'state/_audit/.audit-write.lock'
rm -rf "$SUB/state"

printf '== caller binding (root must know who invoked it) ==\n'
expect_accept 'unprivileged caller is not bound' 'PROBE=ACCEPT' \
  -- "$PROBE" caller-binding 501 '' 'agentmac'
expect_accept 'root with a matching SUDO_USER' 'PROBE=ACCEPT' \
  -- "$PROBE" caller-binding 0 'agentmac' 'agentmac'
expect_reject 'root with NO SUDO_USER' 'no SUDO_USER' \
  -- "$PROBE" caller-binding 0 '' 'agentmac'
expect_reject 'root acting for another account' 'refusing to act for another account' \
  -- "$PROBE" caller-binding 0 'agentmac' 'someone-else'

printf '== etime parsing (the core of the D7 freshness check) ==\n'
expect_accept 'mm:ss'        'seconds=125'   -- "$PROBE" etime '02:05'
expect_accept 'hh:mm:ss'     'seconds=3725'  -- "$PROBE" etime '01:02:05'
expect_accept 'dd-hh:mm:ss'  'seconds=93784' -- "$PROBE" etime '1-02:03:04'
expect_reject 'garbage etime' 'unparseable'  -- "$PROBE" etime 'soon'

printf '== the arm-state probe: is THIS uid confined, according to the product ==\n'
#
# 2026-07-25, the first live supervised run. `kickstart-daemons` treated the
# per-uid gate daemons' expected PRE-ARM absence as a failed restart, so
# iteration 1 could never start on the only kind of host the loop is ever
# started from. What separates "absent and expected" from "absent and wrong" is
# whether the product's own root-owned registry names this uid, and this is
# that decision, driven as a pure function.
#
# `no` is the FAIL-OPEN answer: it is the one that makes a missing gate daemon
# look expected. So the cases below lean on every shape that could return `no`
# by accident -- pretty-printed JSON, a uid that is a PREFIX of the one asked
# about, a second entry after the first -- rather than only on the happy path.
expect_accept 'no registry content names nothing' 'registry-names-uid=no' \
  -- "$PROBE" registry-names-uid '' '503'
expect_accept 'an empty committed set names nothing' 'registry-names-uid=no' \
  -- "$PROBE" registry-names-uid '{"version":1,"committed":[]}' '503'
expect_accept 'a committed entry for this uid is ARMED' 'registry-names-uid=yes' \
  -- "$PROBE" registry-names-uid '{"version":1,"committed":[{"agent_uid":503,"gate_port":49317}]}' '503'
expect_accept 'a committed entry for ANOTHER uid is not this uid' 'registry-names-uid=no' \
  -- "$PROBE" registry-names-uid '{"version":1,"committed":[{"agent_uid":504,"gate_port":49317}]}' '503'
expect_accept 'this uid found behind another entry' 'registry-names-uid=yes' \
  -- "$PROBE" registry-names-uid '{"committed":[{"agent_uid":600},{"agent_uid":503}]}' '503'
expect_accept 'a PRETTY-PRINTED registry still names the uid' 'registry-names-uid=yes' \
  -- "$PROBE" registry-names-uid '{ "agent_uid" : 503 }' '503'
expect_accept 'a uid this one is a PREFIX of is not a match' 'registry-names-uid=no' \
  -- "$PROBE" registry-names-uid '{"committed":[{"agent_uid":5031}]}' '503'
expect_accept 'an absurd number is not this uid, and does not abort the probe' 'registry-names-uid=no' \
  -- "$PROBE" registry-names-uid '{"committed":[{"agent_uid":999999999999999999999}]}' '503'
expect_accept 'the key without a value is not a match' 'registry-names-uid=no' \
  -- "$PROBE" registry-names-uid '{"agent_uid"}' '503'
expect_reject 'uid 0 is refused rather than probed for' 'refusing' \
  -- "$PROBE" registry-names-uid '{"committed":[{"agent_uid":0}]}' '0'
expect_reject 'a non-numeric uid is refused' 'not a plain non-negative integer' \
  -- "$PROBE" registry-names-uid '{}' '5o3'
# ...and the plist path the existence probe asks about is composed, once.
expect_accept 'the daemon plist path is composed from the one constant' \
  'daemon-plist-path=/Library/LaunchDaemons/ai.sanctuaryprotocol.castle-wall.daemon.plist' \
  -- "$PROBE" daemon-plist-path 'ai.sanctuaryprotocol.castle-wall.daemon'
expect_reject 'a label that could escape the plist directory is refused' 'cannot compose a safe plist path' \
  -- "$PROBE" daemon-plist-path '../../etc/passwd'

printf '== host rail: the decision is a HARDWARE FINGERPRINT ==\n'
#
# A live audit of the real machines (2026-07-25) measured the intended drill
# host answering `hostname -s` with the literal string "Mac", and reporting no
# `scutil --get HostName` at all. A name allowlist able to admit that machine
# would admit a large fraction of default-configured Macs. There is no name
# allowlist any more; names are a deny-only belt.
FP_ALLOWED='1111111111111111111111111111111111111111111111111111111111111111'
FP_DENIED='2222222222222222222222222222222222222222222222222222222222222222'
FP_UNKNOWN='3333333333333333333333333333333333333333333333333333333333333333'

# THE REQUIRED CASE: a generic default Mac name is not sufficient to pass.
for generic in 'Mac' 'Macintosh' 'MacBook-Pro' 'localhost' 'Mac.localdomain' 'mini2'; do
  expect_reject "generic name '$generic' cannot pass the host rail" 'fingerprint' \
    -- "$PROBE" host-observed "$FP_UNKNOWN" "$generic" '' '' ''
done
# ...and not even when it IS the drill host's real name, if the hardware is not
# on the list. The name never decides.
expect_reject 'the drill host by name, unknown hardware' 'not on the compiled-in drill-host allowlist' \
  -- "$PROBE" fingerprint-against "$FP_UNKNOWN" "$FP_DENIED" "$FP_ALLOWED"

expect_accept 'the allowlisted hardware' 'PROBE=ACCEPT' \
  -- "$PROBE" fingerprint-against "$FP_ALLOWED" "$FP_DENIED" "$FP_ALLOWED"
expect_reject 'the denylisted hardware' 'un-overridable denylist' \
  -- "$PROBE" fingerprint-against "$FP_DENIED" "$FP_DENIED" "$FP_ALLOWED"
# Deny beats allow, in the SAME identifier space, whatever the order of the
# lists. A denylist keyed on names beside an allowlist keyed on hardware would
# silently stop matching; this is the case that would notice.
expect_reject 'denied hardware that is ALSO on the allowlist' 'un-overridable denylist' \
  -- "$PROBE" fingerprint-against "$FP_DENIED" "$FP_DENIED" "$FP_DENIED $FP_ALLOWED"
# EVERY unusable lookup is a REJECT, never a skip and never a non-match.
expect_reject 'an EMPTY fingerprint' 'no host fingerprint supplied' \
  -- "$PROBE" fingerprint-against '' "$FP_DENIED" "$FP_ALLOWED"
expect_reject 'a truncated fingerprint' 'not 64 hex characters' \
  -- "$PROBE" fingerprint-against '1111' "$FP_DENIED" "$FP_ALLOWED"
expect_reject 'an error string where a fingerprint belongs' 'not 64 hex characters' \
  -- "$PROBE" fingerprint-against 'ioreg: command not found' "$FP_DENIED" "$FP_ALLOWED"
expect_reject 'an upper-case fingerprint' 'not lowercase hex' \
  -- "$PROBE" fingerprint-against 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "$FP_DENIED" "$FP_ALLOWED"
expect_reject 'an EMPTY allowlist admits nothing' 'allowlist is EMPTY' \
  -- "$PROBE" fingerprint-against "$FP_ALLOWED" "$FP_DENIED" ''

printf '== host rail: a HANGING hardware lookup is a rejection ==\n'
#
# ROUND-3, Codex finding 5. Every unusable `ioreg` answer failed closed --
# absent, empty, malformed, lower-case, non-UUID -- except one: a HANG is not an
# answer at all, and a host rail that hangs produces neither evidence nor a
# refusal. An unattended night would simply not happen and nothing would say so.
#
# The lookup is bounded by a watchdog rather than a polling loop, because this
# rail runs on EVERY wrapper invocation and a poll coarse enough to be cheap is
# also coarse enough to add a second to each of them.
SLOWDIR="$SANDBOX/slow-ioreg"
mkdir -p "$SLOWDIR/bin"
printf '#!/bin/bash\nsleep 60\n' > "$SLOWDIR/bin/ioreg"
chmod +x "$SLOWDIR/bin/ioreg"
sed -e "s|^RAILS_SYSTEM_BIN_DIRS=.*|RAILS_SYSTEM_BIN_DIRS='$SLOWDIR/bin /usr/bin /bin /usr/sbin /sbin'|" \
    -e 's|^RAILS_IOREG_TIMEOUT_SECONDS=.*|RAILS_IOREG_TIMEOUT_SECONDS=2|' \
    "$HERE/lib/rails.sh" > "$SLOWDIR/rails.sh"
SLOW_START="$(date +%s)"
expect_reject 'a hanging ioreg is a REJECT, not a hang' 'TIMED OUT' \
  -- bash -c ". '$SLOWDIR/rails.sh'; rails_host_fingerprint_local"
SLOW_ELAPSED=$(( $(date +%s) - SLOW_START ))
if [ "$SLOW_ELAPSED" -le 10 ]; then
  printf 'ok    the hardware lookup was bounded (%ss, deadline 2s)\n' "$SLOW_ELAPSED"
  PASS=$((PASS + 1))
else
  printf 'FAIL  *** the bounded hardware lookup took %ss; the deadline is not being enforced ***\n' "$SLOW_ELAPSED"
  FAIL=$((FAIL + 1))
fi

printf '== host rail: the UUID -> fingerprint reduction ==\n'
expect_accept 'a well-formed hardware UUID' 'PROBE=ACCEPT' \
  -- "$PROBE" host-fingerprint-of 'DC6E6D25-7885-5B37-948A-5C942737CFF4'
expect_reject 'an empty UUID' 'empty hardware UUID' \
  -- "$PROBE" host-fingerprint-of ''
expect_reject 'a truncated UUID' 'not 36 characters' \
  -- "$PROBE" host-fingerprint-of 'DC6E6D25-7885'
expect_reject 'an error message where a UUID belongs' 'not 36 characters' \
  -- "$PROBE" host-fingerprint-of 'ioreg: could not find IOPlatformExpertDevice'
expect_reject 'a lowercase UUID' 'uppercase-hex form' \
  -- "$PROBE" host-fingerprint-of 'dc6e6d25-7885-5b37-948a-5c942737cff4'
expect_reject 'a same-length non-UUID' 'uppercase-hex form' \
  -- "$PROBE" host-fingerprint-of 'ZZZZZZZZ-7885-5B37-948A-5C942737CFF4'
# The reduction must be a FUNCTION: same UUID, same fingerprint, every time.
FP_A="$("$PROBE" host-fingerprint-of 'DC6E6D25-7885-5B37-948A-5C942737CFF4')"
FP_B="$("$PROBE" host-fingerprint-of 'DC6E6D25-7885-5B37-948A-5C942737CFF4')"
FP_C="$("$PROBE" host-fingerprint-of 'AC6E6D25-7885-5B37-948A-5C942737CFF4')"
if [ "$FP_A" = "$FP_B" ] && [ "$FP_A" != "$FP_C" ]; then
  printf 'ok    the fingerprint is stable per machine and differs between machines\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL  the fingerprint is not a stable per-machine function\n'
  FAIL=$((FAIL + 1))
fi

printf '== host rail: names are a DENY-ONLY belt ==\n'
expect_reject 'daily driver by short name' 'un-overridable name denylist' \
  -- "$PROBE" host "$FP_ALLOWED" 'Eriks-MacBook-Air'
expect_reject 'daily driver with .local' 'un-overridable name denylist' \
  -- "$PROBE" host "$FP_ALLOWED" 'Eriks-MacBook-Air.local'
# The `scutil --get ComputerName` form carries spaces and a curly apostrophe,
# so a space-separated denylist cannot hold it literally; the denylist compares
# an aggressively normalized form for exactly this reason.
expect_reject 'daily driver as its ComputerName' 'un-overridable name denylist' \
  -- "$PROBE" host "$FP_ALLOWED" "Erik's MacBook Air"
# The wrapper's ACTUAL call shape. The reviewed wrapper chose between three
# if/elif branches that passed different subsets, and one of them silently
# DROPPED the ComputerName alias. A rail can only refuse what it is shown.
expect_reject 'observed: a denied name in the SECOND position' 'un-overridable name denylist' \
  -- "$PROBE" host-observed "$FP_ALLOWED" 'Mac' 'Eriks-MacBook-Air' '' ''
expect_reject 'observed: a denied name in the LAST position, others empty' 'un-overridable name denylist' \
  -- "$PROBE" host-observed "$FP_ALLOWED" 'Mac' '' '' "Erik's MacBook Air"
# Mini1 reports NO scutil HostName at all, so zero observed names must not be
# an error: the decision does not rest on names.
expect_reject 'observed: no names at all still reaches the fingerprint' 'allowlist' \
  -- "$PROBE" host-observed "$FP_UNKNOWN" '' '' '' ''

printf '== account rail ==\n'
expect_reject 'root by name' 'refusing the root account by name' \
  -- "$PROBE" account operator 'root'
expect_reject 'uid 0 under another name' 'refusing root by uid' \
  -- "$PROBE" uid operator 'toor' 0
expect_accept 'a non-zero uid' 'PROBE=ACCEPT' -- "$PROBE" uid operator 'agentmac' 501
expect_reject 'non-numeric uid' 'not a plain non-negative integer' \
  -- "$PROBE" uid operator 'weird' '0x0'
expect_reject 'nonexistent account' 'does not exist on this host' \
  -- "$PROBE" account operator 'no-such-drill-account'
expect_reject 'option-shaped account' 'must start with a lowercase letter' \
  -- "$PROBE" account operator '-rf'
expect_reject 'shell metacharacters' 'disallowed characters' \
  -- "$PROBE" account operator 'a;id'
expect_accept 'the current account' 'PROBE=ACCEPT' -- "$PROBE" account operator "$ME"
expect_reject 'wrong expected uid' 'expected 999999' \
  -- "$PROBE" account-uid agent "$ME" 999999
expect_accept 'matching expected uid' 'PROBE=ACCEPT' \
  -- "$PROBE" account-uid agent "$ME" "$(id -u)"

printf '== secret-file rail ==\n'
SECRET="$SANDBOX/pass.txt"
printf 'x\n' > "$SECRET"
chmod 0660 "$SECRET"
expect_reject 'group-writable 0660' 'group- or world-WRITABLE' \
  -- "$PROBE" secret "$SECRET" "$ME"
chmod 0640 "$SECRET"
expect_reject 'group-readable 0640' 'readable or writable by group or other' \
  -- "$PROBE" secret "$SECRET" "$ME"
chmod 0600 "$SECRET"
expect_accept 'mode 0600' 'PROBE=ACCEPT'      -- "$PROBE" secret "$SECRET" "$ME"
ln -s "$SECRET" "$SANDBOX/pass-link.txt"
expect_reject 'symlinked secret file' 'is a symlink' \
  -- "$PROBE" secret "$SANDBOX/pass-link.txt" "$ME"

printf '== lock rail ==\n'
LOCK="$SANDBOX/loop.lock"
mkdir -p "$LOCK"
printf '%s\n' "$$" > "$LOCK/pid"
expect_reject 'live holder refuses' 'held by live pid' \
  -- "$PROBE" lock "$LOCK" 2
rm -rf "$LOCK"
expect_accept 'free lock acquires' 'PROBE=ACCEPT' -- "$PROBE" lock "$LOCK" 5

printf '== lock rail: concurrent stale reclaim ==\n'
rm -rf "$LOCK" "$LOCK".stale.* "$LOCK.reclaim" 2>/dev/null || true
mkdir -p "$LOCK"
# A pid that is certainly dead: fork a shell, record its pid, wait for it.
( exit 0 ) & DEAD=$!
wait "$DEAD" 2>/dev/null || true
printf '%s\n' "$DEAD" > "$LOCK/pid"
OUT_A="$SANDBOX/reclaim-a.out"
OUT_B="$SANDBOX/reclaim-b.out"
# The winner HOLDS for five seconds. Without a hold the first process would
# acquire and release faster than the second could contend, and two sequential
# acquisitions of a free lock would look like a race that never happened.
set +e
"$PROBE" lock "$LOCK" 20 5 > "$OUT_A" 2>&1 &
PA=$!
"$PROBE" lock "$LOCK" 20 5 > "$OUT_B" 2>&1 &
PB=$!
wait "$PA"; RA=$?
wait "$PB"; RB=$?
set -e
WINNERS=0
if [ "$RA" -eq 0 ]; then WINNERS=$((WINNERS + 1)); fi
if [ "$RB" -eq 0 ]; then WINNERS=$((WINNERS + 1)); fi
if [ "$WINNERS" -eq 1 ]; then
  printf 'ok    exactly one of two concurrent reclaimers proceeded\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL  expected exactly 1 winner, got %s (a=%s b=%s)\n' "$WINNERS" "$RA" "$RB"
  note "A: $(cat "$OUT_A")"
  note "B: $(cat "$OUT_B")"
  FAIL=$((FAIL + 1))
fi
rm -rf "$LOCK"

printf '== wrapper integrity rail ==\n'
# The committed hash must describe the current repo. This is the check that
# turns "somebody edited rails.sh and forgot to rebuild" into a red test rather
# than a wrapper whose behavior no longer matches its reviewed hash.
expect_accept 'committed wrapper.sha256 is current' 'wrapper hash OK' \
  -- "$HERE/build-wrapper.sh" --verify-hash

ASSEMBLED="$SANDBOX/wrapper-assembled"
"$HERE/build-wrapper.sh" "$ASSEMBLED" >/dev/null
INSTALLED="$SANDBOX/wrapper-installed"
cp "$ASSEMBLED" "$INSTALLED"
expect_accept 'matching repo, hash and install' 'PROBE=ACCEPT' \
  -- "$PROBE" wrapper-hash "$ASSEMBLED" "$INSTALLED" "$HERE/wrapper.sha256"
expect_reject 'installed file missing' 'installed wrapper missing' \
  -- "$PROBE" wrapper-hash "$ASSEMBLED" "$SANDBOX/nope" "$HERE/wrapper.sha256"
DRIFTED="$SANDBOX/wrapper-drifted"
cp "$ASSEMBLED" "$DRIFTED"
printf '# drift\n' >> "$DRIFTED"
expect_reject 'repo drift' 'assembled wrapper does not match' \
  -- "$PROBE" wrapper-hash "$DRIFTED" "$INSTALLED" "$HERE/wrapper.sha256"
expect_reject 'installed drift' 'installed wrapper does not match' \
  -- "$PROBE" wrapper-hash "$ASSEMBLED" "$DRIFTED" "$HERE/wrapper.sha256"
expect_reject 'installed wrapper not root-owned' 'not owned by root' \
  -- "$PROBE" wrapper-ownership "$INSTALLED"
chmod 0666 "$INSTALLED"
expect_reject 'installed wrapper world-writable' 'group- or world-writable' \
  -- "$PROBE" wrapper-ownership "$INSTALLED"
ln -s "$ASSEMBLED" "$SANDBOX/wrapper-link"
expect_reject 'installed wrapper is a symlink' 'is a symlink' \
  -- "$PROBE" wrapper-ownership "$SANDBOX/wrapper-link"

printf '== wrapper check oracle (the BLOCKER regression) ==\n'
#
# This is the case CI missed last time. The reviewed build's tests only ever
# exercised host-reject-first, so they never reached the path rail at all; the
# wrapper happily printed `WRAPPER=ACCEPT storage=` for a path its own rail had
# rejected, then armed the real fortress as root.
#
# The composed wrapper below is the SHIPPED rails plus the SHIPPED wrapper body,
# with exactly two narrow overrides appended after them:
#
#   RAILS_HOST_ALLOW / RAILS_HOST_DENY - the host rail is stubbed to PASS, which
#     is precisely what the review asked for, so execution reaches the path
#     rail. The host rail's own deny-first behavior is proven above at the rail
#     level, where it can be driven deterministically on any machine.
#   wrapper_home_of - points the operator's home at the sandbox, so nothing here
#     reads or writes a real home directory.
#
# Everything under test - wrapper_run_rails, every rail, the check oracle - is
# the real thing.
# The composed wrapper starts from the REAL assembled artifact, byte for byte,
# with the overrides spliced in immediately before its entrypoint line. The
# reviewed selftest hand-concatenated rails.sh + wrapper-main.sh under its own
# `printf '#!/usr/bin/env bash\nset -euo pipefail\n'`, which meant the battery
# that actually runs ON THE DRILL HOST was the one NOT testing the shipped
# header. The header is where the pinned PATH, `set -euo pipefail`, `IFS` and
# `umask` live, and two of those are BLOCKER-defence layers.
TEST_WRAPPER="$SANDBOX/test-wrapper"
# The host allowlist override is now this machine's REAL hardware fingerprint,
# read through the real `rails_host_fingerprint_local`. That is a stronger stub
# than the old name one: the lookup, the shape validation and the hashing all
# actually run, and only the LIST is substituted.
LOCAL_FP="$(bash -c ". '$HERE/lib/rails.sh'; rails_host_fingerprint_local" 2>/dev/null || printf '')"

# compose_wrapper <out> <agent-allowlist>
#
# CONSTANTS ONLY, spliced in immediately before the entrypoint. Never a
# function: the reviewed batteries overrode `wrapper_home_of`, a FUNCTION, and
# mutating it left every test green. Every constant overridden here has its
# SHIPPED value asserted separately, so an override cannot hide a change to what
# actually runs as root.
compose_wrapper() {
  "$HERE/build-wrapper.sh" --stdout \
    | awk -v fp="$LOCAL_FP" -v base="$BASE" -v agents="$2" -v gatebase="${3:-/var/sanctuary-agents}" -v bins="${4:-}" -v runtime="${5:-}" -v plists="${6:-}" -v registry="${7:-}" '
        $0 == "wrapper_main \"$@\"" {
          print "RAILS_HOST_ALLOW_FP=\047" fp "\047"
          print "RAILS_HOST_DENY_FP=\047\047"
          print "RAILS_HOST_DENY=\047\047"
          print "RAILS_DISPOSABLE_BASE=\047" base "\047"
          print "RAILS_AGENT_ACCOUNT_ALLOW=\047" agents "\047"
          print "RAILS_PRODUCT_GATE_HOME_BASE=\047" gatebase "\047"
          if (bins != "") print "RAILS_SYSTEM_BIN_DIRS=\047" bins "\047"
          if (runtime != "") print "RAILS_PRODUCT_GATE_RUNTIME_DIR=\047" runtime "\047"
          if (plists != "") print "RAILS_PRODUCT_LAUNCHDAEMONS_DIR=\047" plists "\047"
          if (registry != "") print "RAILS_PRODUCT_ANCHOR_REGISTRY=\047" registry "\047"
        }
        { print }
      ' > "$1"
  chmod +x "$1"
}

# The DEFAULT test wrapper keeps the SHIPPED (empty) agent allowlist, so the
# refusal it produces is the shipped behavior rather than a fixture.
compose_wrapper "$TEST_WRAPPER" ''
# And one with this account on the agent allowlist, so the agent-taking verbs
# can be exercised past that rail.
TEST_WRAPPER_AGENT="$SANDBOX/test-wrapper-agent"
compose_wrapper "$TEST_WRAPPER_AGENT" "$ME"

# The wrapper-level cases need a machine with a hardware identity, because the
# host rail decides on one. Linux has no IOPlatformExpertDevice, so there the
# rail correctly refuses before reaching anything else and every case below
# would assert the wrong reason.
#
# SKIP, LOUDLY AND COUNTED, never silently. This file's whole subject is that a
# check which could not be made must not be reported as a check that passed,
# and that rule applies to the battery itself first of all. The rail-level
# cases above carry the coverage on every platform; these carry the end-to-end
# verb coverage on the platform the drill actually runs on, which is the only
# platform where the wrapper will ever be installed.
WRAPPER_CASES='yes'
case "$LOCAL_FP" in
  [0-9a-f]*) [ "${#LOCAL_FP}" -eq 64 ] || WRAPPER_CASES='' ;;
  *) WRAPPER_CASES='' ;;
esac
if [ -z "$WRAPPER_CASES" ]; then
  printf 'SKIP  the wrapper-level cases: this machine has no hardware identity\n'
  printf '      (no IOPlatformExpertDevice; the host rail decides on hardware, so\n'
  printf '       every wrapper case here would refuse for that reason and prove\n'
  printf '       nothing). The rail-level cases above ran in full.\n'
  SKIPPED=$((SKIPPED + 1))
fi

if [ -n "$WRAPPER_CASES" ]; then

printf '== the shipped header is what the battery runs ==\n'
HEADER_BAD=0
if ! head -1 "$TEST_WRAPPER" | grep -q '^#!/bin/bash$'; then
  printf 'FAIL  the assembled artifact does not use an ABSOLUTE interpreter\n'; HEADER_BAD=1
fi
if ! grep -q '^PATH=/usr/bin:/bin:/usr/sbin:/sbin$' "$TEST_WRAPPER"; then
  printf 'FAIL  the assembled artifact does not pin PATH\n'; HEADER_BAD=1
fi
if ! grep -q '^set -euo pipefail$' "$TEST_WRAPPER"; then
  printf 'FAIL  the assembled artifact does not set -euo pipefail\n'; HEADER_BAD=1
fi
if [ "$HEADER_BAD" -eq 0 ]; then
  printf 'ok    absolute shebang, pinned PATH, set -euo pipefail\n'
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
fi

expect_reject 'oracle: --storage is not a flag any more' 'unknown or unsupported argument' \
  -- "$TEST_WRAPPER" check --storage "$ANCHOR/.sanctuary" --operator-account "$ME"
expect_reject 'oracle: empty run id' 'run-id is required' \
  -- "$TEST_WRAPPER" check --run-id '' --operator-account "$ME"
expect_reject 'oracle: missing --run-id' 'run-id is required' \
  -- "$TEST_WRAPPER" check --operator-account "$ME"
expect_reject 'oracle: run id with a slash' 'run id rejected' \
  -- "$TEST_WRAPPER" check --run-id 'a/../../.sanctuary' --operator-account "$ME"
expect_reject 'oracle: operator root by name' 'operator account rejected' \
  -- "$TEST_WRAPPER" check --run-id 'good1' --operator-account root
expect_reject 'oracle: unknown flag' 'unknown or unsupported argument' \
  -- "$TEST_WRAPPER" check --run-id 'good1' --operator-account "$ME" --danger
expect_reject 'oracle: unknown verb' 'unknown verb' \
  -- "$TEST_WRAPPER" definitely-not-a-verb --run-id 'good1' --operator-account "$ME"
expect_accept 'oracle: a good run id is accepted' 'WRAPPER=ACCEPT' \
  -- "$TEST_WRAPPER" check --run-id 'good1' --operator-account "$ME"

printf '== per-VERB confinement (only one of seven verbs used to be tested) ==\n'
#
# The BLOCKER lived in `clean-markers`, and the reviewed battery exercised
# `check` and nothing else. Each verb now gets a case, and the two that were
# EXPLOITED get the exploit itself as a fixture.
VICTIM="$SANDBOX/fake-fortress"
mkdir -p "$VICTIM/state/_audit"
printf 'FORTRESS AUDIT LOCK\n' > "$VICTIM/state/_audit/.audit-write.lock"
expect_accept 'mint creates the disposable fortress' 'WRAPPER=OK verb=mint' \
  -- "$TEST_WRAPPER" mint --run-id 'good1' --operator-account "$ME"
LOOPDIR="$ANCHOR/.sanctuary-loop-good1"

expect_accept 'clean-markers on a clean fortress' 'WRAPPER=OK verb=clean-markers' \
  -- "$TEST_WRAPPER" clean-markers --run-id 'good1' --operator-account "$ME"

# THE EXECUTED EXPLOIT, end to end through the real verb.
rm -rf "${LOOPDIR:?}/state"
ln -s "$VICTIM/state" "$LOOPDIR/state"
expect_reject 'clean-markers refuses a symlinked INTERMEDIATE' 'is a symlink' \
  -- "$TEST_WRAPPER" clean-markers --run-id 'good1' --operator-account "$ME"
if [ -f "$VICTIM/state/_audit/.audit-write.lock" ]; then
  printf 'ok    the fortress audit lock survived the symlinked-intermediate exploit\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL  *** clean-markers DELETED a file outside the storage directory ***\n'
  FAIL=$((FAIL + 1))
fi
rm -f "$LOOPDIR/state"
mkdir -p "$LOOPDIR/state/_audit"
ln -s "$VICTIM/state/_audit/.audit-write.lock" "$LOOPDIR/state/_audit/.audit-write.lock"
expect_reject 'clean-markers refuses a symlinked FINAL component' 'is a symlink' \
  -- "$TEST_WRAPPER" clean-markers --run-id 'good1' --operator-account "$ME"
if [ -f "$VICTIM/state/_audit/.audit-write.lock" ]; then
  printf 'ok    the fortress audit lock survived the symlinked-final exploit\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL  *** clean-markers DELETED a file outside the storage directory ***\n'
  FAIL=$((FAIL + 1))
fi
rm -rf "${LOOPDIR:?}/state"

# `arm` needs a root-owned CLI at the compiled-in path, which does not exist on
# a test machine, so what is asserted here is that it refuses BEFORE reaching
# it, and that it never prints ACCEPT.
expect_reject 'arm without an agent account' 'arm requires' \
  -- "$TEST_WRAPPER" arm --run-id 'good1' --operator-account "$ME"
expect_reject 'repair refuses a missing CLI rather than exec-ing anything' 'CLI not found' \
  -- "$TEST_WRAPPER" repair --run-id 'good1' --operator-account "$ME"
expect_reject 'unprotect refuses a missing CLI' 'CLI not found' \
  -- "$TEST_WRAPPER" unprotect --run-id 'good1' --operator-account "$ME"
# `kickstart-daemons` must report the FAILURE of the thing that is its whole
# job. The reviewed verb ran `|| true` and printed WRAPPER=OK regardless.
# The verb behind the pf fail-closed fix, driven directly. `pfctl` needs root
# (and does not exist on Linux at all), so a non-root run here MUST refuse
# rather than print an empty anchor and call it success. That is the whole
# point: "could not read" and "read, and it was empty" must be two answers.
if [ "$(id -u)" -ne 0 ]; then
  expect_reject 'pf-anchor-rules refuses when pfctl cannot run' 'could not read the pf anchor' \
    -- "$TEST_WRAPPER" pf-anchor-rules --run-id 'good1' --operator-account "$ME"
fi
# The verbs whose whole subject is ONE confined agent must say so rather than
# compose a product label out of an empty string. Round 3: `kickstart-daemons`
# had no `--agent-uid` in its call path at all, and the product's labels are
# per-uid, so the labels it restarted could not have existed.
for v in kickstart-daemons gate-state gate-log gate-port; do
  expect_reject "verb $v refuses without an agent principal" 'requires --agent-account and --agent-uid' \
    -- "$TEST_WRAPPER" "$v" --run-id 'good1' --operator-account "$ME"
done
# THE AGENT PRINCIPAL IS COMPILED IN (round-3 M2). `--agent-account` was the one
# surviving caller-supplied steering input and it is the one that decides who
# root acts against. The test wrapper does NOT override
# RAILS_AGENT_ACCOUNT_ALLOW, so the shipped empty list is what refuses here.
expect_reject 'an agent account not on the compiled-in allowlist is refused' \
  'not on the compiled-in drill agent allowlist' \
  -- "$TEST_WRAPPER" arm --run-id 'good1' --operator-account "$ME" \
     --agent-account "$ME" --agent-uid "$(id -u)"
# --passphrase-file was validated root-run surface that reached no verb.
expect_reject 'the dead --passphrase-file flag is gone' 'unknown or unsupported argument' \
  -- "$TEST_WRAPPER" check --run-id 'good1' --operator-account "$ME" --passphrase-file /dev/null
# `retire` removes the whole disposable fortress (round-3 M1: nothing did, ever,
# while the README claimed a nightly teardown).
mkdir -p "$ANCHOR/.sanctuary-loop-retireme"
expect_accept 'retire removes the disposable fortress' 'WRAPPER=OK verb=retire' \
  -- "$TEST_WRAPPER" retire --run-id 'retireme' --operator-account "$ME"
if [ -e "$ANCHOR/.sanctuary-loop-retireme" ]; then
  printf 'FAIL  *** retire exited 0 and the fortress is still there ***\n'
  FAIL=$((FAIL + 1))
else
  printf 'ok    the retired fortress is actually gone\n'
  PASS=$((PASS + 1))
fi
# `fortress-state` names a state for every entry, and `present-empty` is its own
# state because a ZERO-LENGTH audit lock bricks a fortress permanently.
mkdir -p "$LOOPDIR/state/_audit"
: > "$LOOPDIR/state/_audit/.audit-write.lock"
printf 'x' > "$LOOPDIR/exclusive-routing.json"
expect_accept 'fortress-state reports a present marker' 'FORTRESS entry=exclusive-routing.json state=present' \
  -- "$TEST_WRAPPER" fortress-state --run-id 'good1' --operator-account "$ME"
expect_accept 'fortress-state distinguishes a ZERO-LENGTH lock' \
  'FORTRESS entry=state/_audit/.audit-write.lock state=present-empty' \
  -- "$TEST_WRAPPER" fortress-state --run-id 'good1' --operator-account "$ME"
rm -f "$LOOPDIR/exclusive-routing.json" "$LOOPDIR/state/_audit/.audit-write.lock"
expect_accept 'fortress-state reports absence as absence' 'FORTRESS entry=exclusive-routing.json state=absent' \
  -- "$TEST_WRAPPER" fortress-state --run-id 'good1' --operator-account "$ME"
# `gate-log` must REFUSE when there is no log, because the reason-half of the
# probe ladder cannot be evaluated from a log that does not exist.
expect_reject 'gate-log refuses when there is no log to read' 'CANNOT be evaluated' \
  -- "$TEST_WRAPPER_AGENT" gate-log --run-id 'good1' --operator-account "$ME" \
     --agent-account "$ME" --agent-uid "$(id -u)"

# --- gate-port: how a probe learns where its own subject IS (round-5 B1) ---
#
# The gate is a CONNECT proxy on a per-generation loopback port and there is no
# `rdr`, so a request only traverses it if the client was pointed at the port.
# The whole harness had no way to learn that port: `gate_port` appeared in
# `scripts/drill-loop/` only inside comments and inside a `RESULT=PASS ...
# through the gate` string. This verb is where the number comes from, and
# EVERY answer it can give is a named answer.
printf '== gate-port: three answers, never two ==\n'
GATE_RUNTIME="$SANDBOX/gate-runtime"
GATE_UID="$(id -u)"
mkdir -p "$GATE_RUNTIME/$GATE_UID"
TEST_WRAPPER_PORT="$SANDBOX/test-wrapper-port"
compose_wrapper "$TEST_WRAPPER_PORT" "$ME" '' '' "$GATE_RUNTIME"
gate_port_run() {
  "$TEST_WRAPPER_PORT" gate-port --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$GATE_UID"
}
# ABSENT is a real, legitimate state (before arming, after teardown) and it is
# NOT an error. Folding it into either an error or a port is how "no gate" gets
# to look like "port 0".
expect_accept 'no published gate state is state=absent, not an error' \
  'WRAPPER=GATE-PORT state=absent' -- gate_port_run
printf '{"agent_uid":%s,"gate_port":49317,"generation_id":7,"pid":881,"pid_start":"881-1"}' \
  "$GATE_UID" > "$GATE_RUNTIME/$GATE_UID/state.json"
expect_accept 'a published gate state yields the port' \
  "WRAPPER=GATE-PORT state=present port=49317 generation=7" -- gate_port_run
expect_accept 'and the machine-readable verdict line agrees' \
  'WRAPPER=OK verb=gate-port state=present' -- gate_port_run
# THE UID BINDING. Reading one agent's runtime state and reporting it as
# another's would be this harness's own defect class committed by the wrapper.
printf '{"agent_uid":999999,"gate_port":49317,"generation_id":7}' \
  > "$GATE_RUNTIME/$GATE_UID/state.json"
expect_reject 'a runtime state naming ANOTHER uid is refused' 'names agent uid 999999' \
  -- gate_port_run
printf '{"agent_uid":%s,"gate_port":0,"generation_id":7}' "$GATE_UID" \
  > "$GATE_RUNTIME/$GATE_UID/state.json"
expect_reject 'an impossible port is refused, never reported' 'impossible gate_port' \
  -- gate_port_run
printf 'not json at all\n' > "$GATE_RUNTIME/$GATE_UID/state.json"
expect_reject 'an unparseable runtime state is refused' 'no readable gate_port' \
  -- gate_port_run
# A SYMLINKED runtime-state file must never be followed: the gate uid owns its
# own subdir, and root reading through a link the gate uid planted is the
# round-4 gate-log exploit under a new name.
PORT_VICTIM="$SANDBOX/gate-port-victim.json"
printf '{"agent_uid":%s,"gate_port":31337,"generation_id":1}' "$GATE_UID" > "$PORT_VICTIM"
rm -f "$GATE_RUNTIME/$GATE_UID/state.json"
ln -s "$PORT_VICTIM" "$GATE_RUNTIME/$GATE_UID/state.json"
set +e   # declared exception: this run is EXPECTED to exit nonzero
port_link_out="$(gate_port_run 2>&1)"
set -e
case "$port_link_out" in
  *31337*)
    printf 'FAIL  *** root followed a symlinked gate runtime state and reported the port behind it ***\n'
    note "output: $port_link_out"
    FAIL=$((FAIL + 1)) ;;
  *)
    printf 'ok    a symlinked gate runtime state is never followed\n'
    PASS=$((PASS + 1)) ;;
esac
# A HARD-LINKED runtime state must be refused too (round-4 F1 / round-6 M1). A
# hard link shares its target's inode, uid and gid, so the fd-identity rail
# alone cannot see it: the gate uid owns its own runtime uid dir and could
# plant `state.json` as a SECOND NAME for a file outside the approved tree,
# and root would read the target. The refusal is the link count, before open.
rm -f "$GATE_RUNTIME/$GATE_UID/state.json"
ln "$PORT_VICTIM" "$GATE_RUNTIME/$GATE_UID/state.json"
set +e   # declared exception: this run is EXPECTED to exit nonzero
port_link_out="$(gate_port_run 2>&1)"
port_link_rc=$?
set -e
case "$port_link_out" in
  *31337*)
    printf 'FAIL  *** root read a HARD-LINKED gate runtime state and reported the port behind it ***\n'
    note "output: $port_link_out"
    FAIL=$((FAIL + 1)) ;;
  *'hard links'*)
    if [ "$port_link_rc" -ne 0 ]; then
      printf 'ok    a hard-linked gate runtime state is refused, for the link-count reason\n'
      PASS=$((PASS + 1))
    else
      printf 'FAIL  gate-port named the hard link but exited 0\n'
      FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  gate-port neither read the hard link nor refused it for the link-count reason\n'
    note "output: $port_link_out"
    FAIL=$((FAIL + 1)) ;;
esac
rm -f "$GATE_RUNTIME/$GATE_UID/state.json"
printf '{"agent_uid":%s,"gate_port":49317,"generation_id":7}' "$GATE_UID" \
  > "$GATE_RUNTIME/$GATE_UID/state.json"

# --- the link count must be read from the FD, not the pathname (round-6 re-gate)
#
# The static case above is refused by a link count read with an lstat on the
# PATHNAME, which is a SEPARATE namei from the identity lstat and the open
# below it. The re-gate defeated that by execution on both verbs: unlink the
# leaf and hard-link a victim in its place AFTER the count is taken, and the
# count was measured on the DISCARDED file while the identity lstat and the
# open both see the hard link and agree with each other. Root then read a file
# outside the approved tree into the evidence bundle.
#
# This case reproduces that window deterministically -- a `stat` stub that
# answers the link-count question truthfully for the ORIGINAL file and then
# performs the swap, exactly once -- and asserts the refusal now comes from the
# link count read on the HELD FD. One case at the chokepoint covers all three
# privileged readers (gate-log tail, gate-log cursor, gate-port cat); they all
# open through `wrapper_open_safe_file_under` and no root read bypasses it.
SWAPBIN="$SANDBOX/swapbin"
mkdir -p "$SWAPBIN"
cat > "$SWAPBIN/stat" <<'SWAPSTUB'
#!/bin/bash
# TEST-ONLY stat: wins the window between the PATHNAME link-count read and the
# open. It answers the link-count question with the REAL, pre-swap count of the
# real file (so the pathname pre-check legitimately sees 1), then unlinks the
# leaf and hard-links the victim in its place. Fires at most once, so the run
# is deterministic and no LATER stat can be the reason for a refusal.
want=''
for a in "$@"; do
  case "$a" in '%h'|'%l') want='yes' ;; esac
done
args=("$@")
last="${args[$((${#args[@]}-1))]}"
if [ -n "$want" ] && [ -n "${DRILL_TEST_SWAP_LEAF:-}" ] && [ "$last" = "$DRILL_TEST_SWAP_LEAF" ] \
   && [ ! -e "${DRILL_TEST_SWAP_MARKER:-/nonexistent}" ]; then
  if out="$(/usr/bin/stat "$@" 2>/dev/null)"; then
    : > "$DRILL_TEST_SWAP_MARKER"
    rm -f -- "$DRILL_TEST_SWAP_TARGET"
    ln -- "$DRILL_TEST_SWAP_VICTIM" "$DRILL_TEST_SWAP_TARGET"
    printf '%s\n' "$out"
    exit 0
  fi
  exit 1
fi
exec /usr/bin/stat "$@"
SWAPSTUB
chmod +x "$SWAPBIN/stat"
GATE_RUNTIME_SWAP="$SANDBOX/gate-runtime-swap"
mkdir -p "$GATE_RUNTIME_SWAP/$GATE_UID"
SWAP_TARGET="$GATE_RUNTIME_SWAP/$GATE_UID/state.json"
SWAP_VICTIM="$SANDBOX/gate-port-swap-victim.json"
SWAP_MARKER="$SANDBOX/gate-port-swap-fired"
rm -f "$SWAP_MARKER"
printf '{"agent_uid":%s,"gate_port":49317,"generation_id":7}' "$GATE_UID" > "$SWAP_TARGET"
printf '{"agent_uid":%s,"gate_port":31337,"generation_id":1}' "$GATE_UID" > "$SWAP_VICTIM"
TEST_WRAPPER_PORT_SWAP="$SANDBOX/test-wrapper-port-swap"
compose_wrapper "$TEST_WRAPPER_PORT_SWAP" "$ME" '' "$SWAPBIN /usr/bin /bin /usr/sbin /sbin" "$GATE_RUNTIME_SWAP"
set +e   # declared exception: this run is EXPECTED to exit nonzero
port_swap_out="$(DRILL_TEST_SWAP_LEAF='state.json' DRILL_TEST_SWAP_MARKER="$SWAP_MARKER" \
  DRILL_TEST_SWAP_TARGET="$SWAP_TARGET" DRILL_TEST_SWAP_VICTIM="$SWAP_VICTIM" \
  "$TEST_WRAPPER_PORT_SWAP" gate-port --run-id 'good1' --operator-account "$ME" \
  --agent-account "$ME" --agent-uid "$GATE_UID" 2>&1)"
port_swap_rc=$?
set -e
# ANTI-VACUITY on the FIXTURE, not on the verdict: if the stub never fired, the
# wrapper read the untouched state.json and this case proves nothing about the
# window. Assert the swap actually happened -- the leaf must now BE the victim,
# by identity, and carry two links.
swap_leaf_id="$(bash -c ". '$HERE/lib/rails.sh'; rails__stat_identity '$SWAP_TARGET'")"
swap_victim_id="$(bash -c ". '$HERE/lib/rails.sh'; rails__stat_identity '$SWAP_VICTIM'")"
swap_leaf_nlink="$(bash -c ". '$HERE/lib/rails.sh'; rails__stat_nlink '$SWAP_TARGET'")"
if [ ! -e "$SWAP_MARKER" ] || [ "$swap_leaf_id" != "$swap_victim_id" ] || [ "$swap_leaf_nlink" != '2' ]; then
  printf 'FAIL  anti-vacuity: the swap never happened, so the window was never exercised\n'
  note "marker=$([ -e "$SWAP_MARKER" ] && printf fired || printf absent) leaf=$swap_leaf_id victim=$swap_victim_id nlink=$swap_leaf_nlink"
  FAIL=$((FAIL + 1))
else
  case "$port_swap_out" in
    *31337*)
      printf 'FAIL  *** root read a file hard-linked in AFTER the pathname link-count check ***\n'
      note "output: $port_swap_out"
      FAIL=$((FAIL + 1)) ;;
    *'hard links'*)
      if [ "$port_swap_rc" -ne 0 ]; then
        printf 'ok    a leaf hard-linked inside the link-count window is refused from the held fd\n'
        PASS=$((PASS + 1))
      else
        printf 'FAIL  gate-port named the raced hard link but exited 0\n'
        FAIL=$((FAIL + 1))
      fi ;;
    *)
      printf 'FAIL  gate-port neither read the raced hard link nor refused it for the link-count reason\n'
      note "output: $port_swap_out"
      FAIL=$((FAIL + 1)) ;;
  esac
fi
rm -f "$SWAP_TARGET" "$SWAP_VICTIM" "$SWAP_MARKER"

# --- gate-port under the REAL-HOST ownership shape (round-6 H1) -------------
#
# On a real host the product chowns `gate-runtime/<uid>` to the GATE uid
# (`server/src/egress-gate/runtime-fs-plan.ts`), so the root-run reader is NOT
# the owner of the leaf dir and the owner is NOT root. Every other case in this
# battery has self == owner for every component, so the one ownership condition
# this verb exists to cross was structurally unexercised -- and the round-6
# gate-port deterministically died on it, turning every through-gate probe
# UNOBSERVED on the platform that matters. This case injects the foreign owner
# through a `stat` that lies ONLY about the uid dir's owner, reproducing the
# production trust shape in the sandbox: trusted base, leaf dir owned by
# SOMEBODY ELSE.
STATBIN="$SANDBOX/statbin"
mkdir -p "$STATBIN"
cat > "$STATBIN/stat" <<'STATSTUB'
#!/bin/bash
# TEST-ONLY stat: reports a foreign owner uid for ONE directory, real facts
# for everything else.
if [ -n "${DRILL_TEST_FOREIGN_DIR:-}" ]; then
  args=("$@")
  last="${args[$((${#args[@]}-1))]}"
  if [ "$last" = "$DRILL_TEST_FOREIGN_DIR" ]; then
    for a in "$@"; do
      case "$a" in
        '%u') echo 555; exit 0 ;;
      esac
    done
  fi
fi
exec /usr/bin/stat "$@"
STATSTUB
chmod +x "$STATBIN/stat"
GATE_RUNTIME_FOREIGN="$SANDBOX/gate-runtime-foreign"
mkdir -p "$GATE_RUNTIME_FOREIGN/$GATE_UID"
printf '{"agent_uid":%s,"gate_port":49317,"generation_id":7}' "$GATE_UID" \
  > "$GATE_RUNTIME_FOREIGN/$GATE_UID/state.json"
# ANTI-VACUITY, first: prove the injected owner IS what the ownership rail
# refuses when the rail is pointed at the uid dir. A stub that never fired
# would make the accept case below vacuous (the neutered-guard lesson: attack
# the guard by neutering it, not only by feeding it a violation).
foreign_rail_direct() {
  DRILL_TEST_FOREIGN_DIR="$GATE_RUNTIME_FOREIGN/$GATE_UID" bash -c \
    ". '$HERE/lib/rails.sh'; RAILS_SYSTEM_BIN_DIRS='$STATBIN /usr/bin /bin /usr/sbin /sbin'; rails_assert_trusted_dir_chain 'foreign dir' '$GATE_RUNTIME_FOREIGN/$GATE_UID'"
}
expect_reject 'anti-vacuity: the injected foreign owner IS refused by the ownership rail' \
  'owned by uid 555' -- foreign_rail_direct
# THE CASE ITSELF. The composed wrapper resolves `stat` through the stub dir,
# so the uid dir reports owner 555 while the caller is neither 555 nor root:
# exactly the shape the round-6 wrapper died on. The fixed verb trust-chains
# only the root-owned base and hand-walks the gate-owned remainder, so it must
# still yield the port.
TEST_WRAPPER_PORT_FOREIGN="$SANDBOX/test-wrapper-port-foreign"
compose_wrapper "$TEST_WRAPPER_PORT_FOREIGN" "$ME" '' "$STATBIN /usr/bin /bin /usr/sbin /sbin" "$GATE_RUNTIME_FOREIGN"
gate_port_foreign_run() {
  DRILL_TEST_FOREIGN_DIR="$GATE_RUNTIME_FOREIGN/$GATE_UID" \
    "$TEST_WRAPPER_PORT_FOREIGN" gate-port --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$GATE_UID"
}
expect_accept 'a gate-owned runtime uid dir (reader != owner != root) still yields the port' \
  'WRAPPER=GATE-PORT state=present port=49317 generation=7' -- gate_port_foreign_run

# --- gate-log reads OUTSIDE the fortress through the same chokepoint -------
#
# The gate homes are not under `$STORAGE`, which is exactly why this verb must
# extend the path-resolution chokepoint to that root instead of hand-checking a
# few components at the call site.
#
# The LOG DIR is the component that matters and the one a first pass at this verb
# missed. `[ -L "$f" ]` lstats only the FINAL component, so a symlinked `logs/`
# would be followed by the kernel and never looked at, which is exactly the
# round-2 unchecked-intermediate exploit -- here it would let the gate uid make
# ROOT `tail` an arbitrary file into the evidence bundle.
GATEBASE="$SANDBOX/gate-homes"
GATEACCOUNT="$(bash -c ". '$HERE/lib/rails.sh'; rails_product_gate_account_for_agent_account '$ME'")"
GATEHOME="$GATEBASE/$GATEACCOUNT"
mkdir -p "$GATEHOME/logs"
printf 'peer=%s allowlist ok\n' "$(id -u)" > "$GATEHOME/logs/egress-gate-$(id -u).out.log"
TEST_WRAPPER_GATE="$SANDBOX/test-wrapper-gate"
compose_wrapper "$TEST_WRAPPER_GATE" "$ME" "$GATEBASE"
expect_accept 'gate-log reads the log the PRODUCT writes' 'WRAPPER=OK verb=gate-log' \
  -- "$TEST_WRAPPER_GATE" gate-log --run-id 'good1' --operator-account "$ME" \
     --agent-account "$ME" --agent-uid "$(id -u)"
expect_accept 'gate-log returns the gate log CONTENT' "peer=$(id -u) allowlist ok" \
  -- "$TEST_WRAPPER_GATE" gate-log --run-id 'good1' --operator-account "$ME" \
     --agent-account "$ME" --agent-uid "$(id -u)"
# Now make the LOG DIR a symlink at a victim holding a secret. Root must refuse
# rather than tail whatever the link points at.
GATE_VICTIM="$SANDBOX/gate-log-victim"
mkdir -p "$GATE_VICTIM"
printf 'SECRET-OUTSIDE-THE-GATE-HOME\n' > "$GATE_VICTIM/egress-gate-$(id -u).out.log"
rm -rf "${GATEHOME:?}/logs"
ln -s "$GATE_VICTIM" "$GATEHOME/logs"
expect_reject 'a SYMLINKED gate log directory is refused' 'unsafe gate_out path' \
  -- "$TEST_WRAPPER_GATE" gate-log --run-id 'good1' --operator-account "$ME" \
     --agent-account "$ME" --agent-uid "$(id -u)"
set +e   # declared exception: this run is EXPECTED to exit nonzero
gate_out="$("$TEST_WRAPPER_GATE" gate-log --run-id 'good1' --operator-account "$ME" \
  --agent-account "$ME" --agent-uid "$(id -u)" 2>&1)"
set -e
case "$gate_out" in
  *SECRET-OUTSIDE-THE-GATE-HOME*)
    printf 'FAIL  *** root followed a symlinked log dir and printed a file outside the gate home ***\n'
    FAIL=$((FAIL + 1)) ;;
  *)
    printf 'ok    the file behind the symlinked log dir was never read\n'
    PASS=$((PASS + 1)) ;;
esac
rm -f "$GATEHOME/logs"
mkdir -p "$GATEHOME/logs"
ATTACK_LOG="$GATEHOME/logs/egress-gate-$(id -u).out.log"
printf 'SAFE-GATE-LOG peer=%s\n' "$(id -u)" > "$ATTACK_LOG"
TAIL_VICTIM="$SANDBOX/gate-tail-victim.log"
printf 'SECRET-TAIL-SUBSTITUTED\n' > "$TAIL_VICTIM"
TAILBIN="$SANDBOX/tailbin"
mkdir -p "$TAILBIN"
cat > "$TAILBIN/tail" <<'TAILSTUB'
#!/bin/bash
args=("$@")
last="${args[$((${#args[@]}-1))]}"
if [ -n "${DRILL_TEST_ATTACK_PATH:-}" ] && [ "$last" = "$DRILL_TEST_ATTACK_PATH" ]; then
  rm -f -- "$last"
  ln -s -- "$DRILL_TEST_VICTIM" "$last"
fi
exec /usr/bin/tail "$@"
TAILSTUB
chmod +x "$TAILBIN/tail"
TEST_WRAPPER_GATE_TAIL="$SANDBOX/test-wrapper-gate-tail"
compose_wrapper "$TEST_WRAPPER_GATE_TAIL" "$ME" "$GATEBASE" "$TAILBIN /usr/bin /bin /usr/sbin /sbin"
set +e   # declared exception: this run may reject if the path is substituted
gate_out="$(DRILL_TEST_ATTACK_PATH="$ATTACK_LOG" DRILL_TEST_VICTIM="$TAIL_VICTIM" \
  "$TEST_WRAPPER_GATE_TAIL" gate-log --run-id 'good1' --operator-account "$ME" \
  --agent-account "$ME" --agent-uid "$(id -u)" 2>&1)"
gate_rc=$?
set -e
case "$gate_out" in
  *SECRET-TAIL-SUBSTITUTED*)
    printf 'FAIL  *** gate-log reopened a mutable pathname and printed a substituted file ***\n'
    FAIL=$((FAIL + 1)) ;;
  *SAFE-GATE-LOG*)
    if [ "$gate_rc" -eq 0 ]; then
      printf 'ok    gate-log reads the checked fd, not a path tail can be raced under it\n'
      PASS=$((PASS + 1))
    else
      printf 'FAIL  gate-log avoided the secret but exited %s\n' "$gate_rc"
      note "output: $gate_out"; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  gate-log neither read the safe log nor exposed the substitution clearly\n'
    note "output: $gate_out"; FAIL=$((FAIL + 1)) ;;
esac
# A HARD-LINKED gate log leaf must be refused (round-4 F1 / round-6 M1). The
# gate uid owns `logs/`, and a hard link at the log name shares its target's
# inode/uid/gid, so the fd-identity rail alone would let root tail an
# ARBITRARY file into the evidence bundle. The suite already refused a
# symlinked leaf and a symlinked dir; this is the third alias shape.
LINK_VICTIM="$SANDBOX/gate-log-link-victim.log"
printf 'SECRET-BEHIND-A-HARD-LINK\n' > "$LINK_VICTIM"
rm -f "$ATTACK_LOG"
ln "$LINK_VICTIM" "$ATTACK_LOG"
set +e   # declared exception: this run is EXPECTED to exit nonzero
gate_out="$("$TEST_WRAPPER_GATE" gate-log --run-id 'good1' --operator-account "$ME" \
  --agent-account "$ME" --agent-uid "$(id -u)" 2>&1)"
gate_rc=$?
set -e
case "$gate_out" in
  *SECRET-BEHIND-A-HARD-LINK*)
    printf 'FAIL  *** root tailed a HARD-LINKED gate log and printed the file behind it ***\n'
    note "output: $gate_out"; FAIL=$((FAIL + 1)) ;;
  *'hard links'*)
    if [ "$gate_rc" -ne 0 ]; then
      printf 'ok    a hard-linked gate log leaf is refused, for the link-count reason\n'
      PASS=$((PASS + 1))
    else
      printf 'FAIL  gate-log named the hard link but exited 0\n'
      FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  gate-log neither printed the hard-linked content nor refused it for the link-count reason\n'
    note "output: $gate_out"; FAIL=$((FAIL + 1)) ;;
esac
rm -f "$ATTACK_LOG" "$LINK_VICTIM"
printf 'SAFE-GATE-LOG peer=%s\n' "$(id -u)" > "$ATTACK_LOG"
# ...and the same account IS accepted once it is on the allowlist, so the rail
# has been seen to say yes as well as no.
expect_reject 'an allowlisted agent account passes the agent rail and dies later' 'kickstart failed for' \
  -- "$TEST_WRAPPER_AGENT" kickstart-daemons --run-id 'good1' --operator-account "$ME" \
     --agent-account "$ME" --agent-uid "$(id -u)"

printf '== kickstart-daemons: ABSENT-BEFORE-ARM is not a failed restart ==\n'
#
# THE FIRST LIVE SUPERVISED RUN (Mini1, 2026-07-25) stopped at step 0 of
# iteration 1 on a host where nothing was wrong:
#
#   WRAPPER=REJECT reason=kickstart failed for: ai.sanctuaryprotocol.egress-gate.503
#     ai.sanctuaryprotocol.egress-gate-peer-resolver.503 (restarted: none)
#
# Those are the PER-UID gate daemons, and the ARM creates them -- three steps
# LATER in the same ladder. So on a clean, disarmed host they legitimately do
# not exist, the verb read `launchctl kickstart`'s non-zero exit as a failed
# restart, and no iteration could ever begin. `(restarted: none)` was equally
# what a total restart failure and a nothing-to-restart host look like.
#
# Four cases, because the verb now has four outcomes and every one of them has
# a way of being wrong:
#
#   A  absent BEFORE the arm      accepted, and named as expected
#   B  present                    restarted, whatever the arm state
#   C  present and will not restart   still a hard FAIL, unchanged
#   D  absent AFTER the arm       a FAIL, so the fix is not blindness
#
# ANTI-VACUITY IS ON THE FIXTURE, not on the verdict: each case asserts that
# the launchctl stub was actually ASKED (its log) and that the plists it screens
# are actually in the state the case claims. A verdict alone cannot tell a
# wrapper that looked from a wrapper that guessed, which is the entire subject.
KICKBIN="$SANDBOX/kickbin"
mkdir -p "$KICKBIN"
cat > "$KICKBIN/launchctl" <<'KICKSTUB'
#!/bin/bash
# TEST-ONLY launchctl. `print` answers ONLY for labels in
# DRILL_TEST_LAUNCHD_LOADED; `kickstart` fails for labels in
# DRILL_TEST_LAUNCHD_KICK_FAIL. Every invocation is logged, so a case can prove
# the wrapper asked the question rather than inferred the answer.
verb="$1"
target=''
for a in "$@"; do case "$a" in system/*) target="${a#system/}" ;; esac; done
if [ -n "${DRILL_TEST_LAUNCHD_LOG:-}" ]; then
  printf '%s %s\n' "$verb" "$target" >> "$DRILL_TEST_LAUNCHD_LOG"
fi
case "$verb" in
  print)
    case " ${DRILL_TEST_LAUNCHD_LOADED:-} " in
      *" $target "*) printf 'state = running\n'; exit 0 ;;
    esac
    printf 'Could not find service "%s"\n' "$target" >&2
    exit 113 ;;
  kickstart)
    case " ${DRILL_TEST_LAUNCHD_KICK_FAIL:-} " in
      *" $target "*) printf 'Could not kickstart service "%s"\n' "$target" >&2; exit 5 ;;
    esac
    exit 0 ;;
esac
exit 0
KICKSTUB
chmod +x "$KICKBIN/launchctl"

KICK_PLISTS="$SANDBOX/launchdaemons"
KICK_REGDIR="$SANDBOX/kick-registry"
mkdir -p "$KICK_PLISTS" "$KICK_REGDIR"
KICK_REG="$KICK_REGDIR/egress-anchor-registry.json"
KICK_LOG="$SANDBOX/kick-launchctl.log"
TEST_WRAPPER_KICK="$SANDBOX/test-wrapper-kickstart"
compose_wrapper "$TEST_WRAPPER_KICK" "$ME" '' \
  "$KICKBIN /usr/bin /bin /usr/sbin /sbin" '' "$KICK_PLISTS" "$KICK_REG"

KICK_UID="$(id -u)"
# COMPOSED, never re-spelled: a second declaration site for a product label is
# how four of them drifted at once in round 3.
KICK_HOSTS="$(bash -c ". '$HERE/lib/rails.sh'; rails_product_host_daemon_labels")"
KICK_GATES="$(bash -c ". '$HERE/lib/rails.sh'; rails_product_daemon_labels '$KICK_UID'")"
KICK_HOST_A="${KICK_HOSTS%% *}"
KICK_HOST_B="${KICK_HOSTS##* }"
KICK_GATE="${KICK_GATES%% *}"
KICK_PEER="${KICK_GATES##* }"

kick_plant_plists() {
  rm -f "$KICK_PLISTS"/*.plist
  local l
  for l in "$@"; do printf '<plist/>\n' > "$KICK_PLISTS/$l.plist"; done
}
kick_registry_naming() {
  # $1 empty -> no registry file at all (nothing on this host is confined)
  if [ -z "${1:-}" ]; then rm -f "$KICK_REG"; return 0; fi
  printf '{"version":1,"committed":[{"agent_uid":%s,"gate_port":49317,"fortress_path":"/private/var/sanctuary-drill/x"}]}' "$1" > "$KICK_REG"
}
run_kickstart() {
  # run_kickstart <loaded labels> <kickstart-failing labels>
  : > "$KICK_LOG"
  DRILL_TEST_LAUNCHD_LOG="$KICK_LOG" \
  DRILL_TEST_LAUNCHD_LOADED="${1:-}" \
  DRILL_TEST_LAUNCHD_KICK_FAIL="${2:-}" \
  "$TEST_WRAPPER_KICK" kickstart-daemons --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$KICK_UID" 2>&1
}
kick_log_has() { grep -qxF "$1" "$KICK_LOG"; }

# --- A: absent BEFORE the arm is the expected state, not a failure ---------
kick_plant_plists "$KICK_HOST_A" "$KICK_HOST_B"
kick_registry_naming ''
set +e   # declared exception
kick_out="$(run_kickstart "$KICK_HOST_A $KICK_HOST_B" '')"; kick_rc=$?
set -e
if [ -e "$KICK_PLISTS/$KICK_GATE.plist" ] || [ -e "$KICK_PLISTS/$KICK_PEER.plist" ] \
   || [ -e "$KICK_REG" ] || ! kick_log_has "print $KICK_GATE"; then
  printf 'FAIL  anti-vacuity: the pre-arm fixture was not pre-arm, or the wrapper never LOOKED for the gate daemon\n'
  note "log: $(cat "$KICK_LOG" 2>/dev/null || true)"
  FAIL=$((FAIL + 1))
else
  case "$kick_out" in
    *'arm_state=not-armed arm_basis=registry-absent'*"restarted=$KICK_HOST_A,$KICK_HOST_B"*"absent_expected=$KICK_GATE,$KICK_PEER"*'absent_unexpected=- restart_failed=-'*)
      if [ "$kick_rc" -eq 0 ] && kick_log_has "kickstart $KICK_HOST_A" && kick_log_has "kickstart $KICK_HOST_B"; then
        printf 'ok    a per-uid gate daemon that does not exist YET is absent-and-expected, and the host daemons still restart\n'
        PASS=$((PASS + 1))
      else
        printf 'FAIL  the pre-arm verdict was right but the host daemons were not actually restarted (rc=%s)\n' "$kick_rc"
        note "log: $(cat "$KICK_LOG" 2>/dev/null || true)"; FAIL=$((FAIL + 1))
      fi ;;
    *'kickstart failed for'*)
      printf 'FAIL  *** a clean pre-arm host STILL cannot start iteration 1: absence read as a failed restart ***\n'
      note "output: $kick_out"; FAIL=$((FAIL + 1)) ;;
    *)
      printf 'FAIL  kickstart produced no recognizable three-way verdict on a pre-arm host\n'
      note "output: $kick_out"; FAIL=$((FAIL + 1)) ;;
  esac
fi

# --- B: a daemon that EXISTS is restarted, and existence is OBSERVED -------
# The gate plists are on disk but NOT loaded in launchd, so the plist limb of
# the existence probe is the one that has to answer. A probe that only asked
# `launchctl print` would call these absent and, being armed, FAIL.
kick_plant_plists "$KICK_HOST_A" "$KICK_HOST_B" "$KICK_GATE" "$KICK_PEER"
kick_registry_naming "$KICK_UID"
set +e   # declared exception
kick_out="$(run_kickstart "$KICK_HOST_A $KICK_HOST_B" '')"; kick_rc=$?
set -e
if [ ! -e "$KICK_PLISTS/$KICK_GATE.plist" ] || [ ! -s "$KICK_REG" ]; then
  printf 'FAIL  anti-vacuity: the armed fixture was never planted\n'; FAIL=$((FAIL + 1))
elif kick_log_has "kickstart $KICK_GATE" && kick_log_has "kickstart $KICK_PEER" \
     && kick_log_has "kickstart $KICK_HOST_A" && kick_log_has "kickstart $KICK_HOST_B"; then
  case "$kick_out" in
    *'arm_state=armed arm_basis=registry-names-uid'*"restarted=$KICK_HOST_A,$KICK_HOST_B,$KICK_GATE,$KICK_PEER"*'absent_expected=- absent_unexpected=- restart_failed=-'*)
      if [ "$kick_rc" -eq 0 ]; then
        printf 'ok    every daemon that EXISTS is restarted, plist-present counts as existing\n'
        PASS=$((PASS + 1))
      else
        printf 'FAIL  every daemon restarted but the verb exited %s\n' "$kick_rc"
        note "output: $kick_out"; FAIL=$((FAIL + 1))
      fi ;;
    *)
      printf 'FAIL  a present-and-restarted host did not produce the all-restarted verdict\n'
      note "output: $kick_out"; FAIL=$((FAIL + 1)) ;;
  esac
else
  printf 'FAIL  anti-vacuity: the wrapper never asked launchctl to restart the planted daemons\n'
  note "log: $(cat "$KICK_LOG" 2>/dev/null || true)"; FAIL=$((FAIL + 1))
fi

# --- C: a PRESENT daemon that will not restart is still a hard FAIL --------
# The registry is silent on this uid here, so the case also proves the arm
# state governs only what an ABSENCE means: a gate daemon that is present is
# restarted, and its failure is fatal, armed or not.
kick_plant_plists "$KICK_HOST_A" "$KICK_HOST_B" "$KICK_GATE" "$KICK_PEER"
kick_registry_naming "$((KICK_UID + 1))"
set +e   # declared exception: this run is EXPECTED to exit nonzero
kick_out="$(run_kickstart "$KICK_HOST_A $KICK_HOST_B" "$KICK_GATE")"; kick_rc=$?
set -e
if ! kick_log_has "kickstart $KICK_GATE"; then
  printf 'FAIL  anti-vacuity: the failing restart was never attempted\n'
  note "log: $(cat "$KICK_LOG" 2>/dev/null || true)"; FAIL=$((FAIL + 1))
else
  case "$kick_out" in
    *"kickstart failed for: $KICK_GATE"*"restart_failed=$KICK_GATE"*)
      if [ "$kick_rc" -ne 0 ]; then
        printf 'ok    a PRESENT daemon that will not restart is still fatal, and named as restart_failed\n'
        PASS=$((PASS + 1))
      else
        printf 'FAIL  a daemon refused to restart and the verb exited 0\n'
        note "output: $kick_out"; FAIL=$((FAIL + 1))
      fi ;;
    *'WRAPPER=OK verb=kickstart-daemons'*)
      printf 'FAIL  *** a failed restart printed OK over itself ***\n'
      note "output: $kick_out"; FAIL=$((FAIL + 1)) ;;
    *)
      printf 'FAIL  a failed restart produced no recognizable refusal\n'
      note "output: $kick_out"; FAIL=$((FAIL + 1)) ;;
  esac
fi

# --- D: absent AFTER the arm is a FAILURE, so this is not blindness --------
kick_plant_plists "$KICK_HOST_A" "$KICK_HOST_B"
kick_registry_naming "$KICK_UID"
set +e   # declared exception: this run is EXPECTED to exit nonzero
kick_out="$(run_kickstart "$KICK_HOST_A $KICK_HOST_B" '')"; kick_rc=$?
set -e
if [ ! -s "$KICK_REG" ] || [ -e "$KICK_PLISTS/$KICK_GATE.plist" ]; then
  printf 'FAIL  anti-vacuity: the armed-but-absent fixture was never planted\n'; FAIL=$((FAIL + 1))
else
  case "$kick_out" in
    *"kickstart failed for: $KICK_GATE $KICK_PEER"*"absent_unexpected=$KICK_GATE,$KICK_PEER"*)
      if [ "$kick_rc" -ne 0 ]; then
        printf 'ok    a gate daemon missing while the registry says this uid is CONFINED is a failure, not an expected absence\n'
        PASS=$((PASS + 1))
      else
        printf 'FAIL  an armed uid with no gate daemon exited 0\n'
        note "output: $kick_out"; FAIL=$((FAIL + 1))
      fi ;;
    *'WRAPPER=OK verb=kickstart-daemons'*)
      printf 'FAIL  *** the harness is BLIND: a gate daemon that should exist by now read as expected-absent ***\n'
      note "output: $kick_out"; FAIL=$((FAIL + 1)) ;;
    *)
      printf 'FAIL  an armed-but-absent gate daemon produced no recognizable refusal\n'
      note "output: $kick_out"; FAIL=$((FAIL + 1)) ;;
  esac
fi
rm -f "$KICK_PLISTS"/*.plist "$KICK_REG"
# Every verb refuses a bad run id before doing anything at all.
for v in mint clean-markers gate-state kickstart-daemons repair unprotect retire \
         pf-anchor-rules registry-state fortress-state gate-log gate-port; do
  expect_reject "verb $v refuses a traversal run id" 'run id rejected' \
    -- "$TEST_WRAPPER" "$v" --run-id '../../.sanctuary' --operator-account "$ME"
done

printf '== teardown-verify: a check that could not OBSERVE is not CLEAN ==\n'
#
# The reviewed driver did `rules="$(sudo -n pfctl ... || printf '')"` and read
# the empty string as CLEAN, while the README said plainly that the pfctl grant
# does not exist. On the first unattended night it would have reported CLEAN
# having observed nothing, which is the 2026-06-24 "claimed all drills dry"
# failure automated and running every night.
#
# HOW THE STUB IS REACHED, AND WHY IT IS NOT PATH ANY MORE.
#
# ROUND-3 BLOCKER 1: the previous version of this battery put a stub `sudo`
# earlier in PATH, which worked because the drivers resolved `sudo` through
# PATH. That is the defect: Codex used the same trick to make the real probe
# battery print a full green ladder and the real teardown print CLEAN, with no
# sudo, no wrapper, no pfctl and no agent account.
#
# The drivers now resolve every tool their evidence rests on through
# `rails__abs_cmd`, which only ever looks in `$RAILS_SYSTEM_BIN_DIRS`. So the
# battery composes a SANDBOX COPY of the harness whose `RAILS_SYSTEM_BIN_DIRS`
# CONSTANT names the stub directory first -- exactly the same discipline the
# wrapper battery uses, a constant and never a function -- and the SHIPPED value
# of that constant is asserted separately. There is no environment variable and
# no flag that reaches the resolver in production.
STUBBIN="$SANDBOX/stubbin"
mkdir -p "$STUBBIN"
cat > "$STUBBIN/sudo" <<'STUB'
#!/bin/bash
# TEST-ONLY stand-in for sudo. Understands the two shapes the drivers use:
# `sudo -n <wrapper> <verb> ...` and `sudo -n -u <acct> -- <abs-cmd> ...`.
if [ -n "${STUB_SUDO_LOG:-}" ]; then printf '%s\n' "$*" >> "$STUB_SUDO_LOG"; fi
args=("$@")
for a in "${args[@]}"; do
  case "$a" in
    pf-anchor-rules)
      if [ "${STUB_PF:-ok}" = 'refused' ]; then
        echo 'sudo: a password is required' >&2
        exit 1
      fi
      echo 'WRAPPER=PF-ANCHOR-BEGIN'
      printf '%s\n' "${STUB_PF_RULES:-}"
      echo 'WRAPPER=PF-ANCHOR-END'
      echo 'WRAPPER=OK verb=pf-anchor-rules'
      exit 0
      ;;
    registry-state)
      case "${STUB_REGISTRY:-absent}" in
        refused) echo 'sudo: a password is required' >&2; exit 1 ;;
        absent)  echo 'WRAPPER=REGISTRY-ABSENT path=/var/db/sanctuary/egress-anchor-registry.json'
                 echo 'WRAPPER=OK verb=registry-state state=absent'; exit 0 ;;
        *)       echo 'WRAPPER=REGISTRY-BEGIN path=/var/db/sanctuary/egress-anchor-registry.json'
                 printf '%s\n' "${STUB_REGISTRY_BODY:-}"
                 echo 'WRAPPER=REGISTRY-END'
                 echo 'WRAPPER=OK verb=registry-state state=present'; exit 0 ;;
      esac
      ;;
    fortress-state)
      if [ "${STUB_FORTRESS:-ok}" = 'refused' ]; then
        echo 'sudo: a password is required' >&2
        exit 1
      fi
      echo "WRAPPER=FORTRESS-BEGIN storage=${STUB_STORAGE:-}"
      printf 'FORTRESS entry=exclusive-routing.json state=%s\n' "${STUB_MARKER:-absent}"
      printf 'FORTRESS entry=state/_audit/.audit-write.lock state=%s\n' "${STUB_AUDIT_LOCK:-absent}"
      printf 'FORTRESS entry=state/.provision.lock state=%s\n' "${STUB_PROVISION_LOCK:-absent}"
      echo 'WRAPPER=FORTRESS-END'
      echo 'WRAPPER=OK verb=fortress-state'
      exit 0
      ;;
    gate-log)
      if [ "${STUB_GATE_LOG:-refused}" = 'refused' ]; then
        echo 'WRAPPER=REJECT reason=no gate log' >&2
        exit 20
      fi
      cursor_only=''
      since_mode=''
      for x in "${args[@]}"; do
        if [ "$x" = '--log-cursor-only' ]; then cursor_only='yes'; fi
        case "$x" in --since-*) since_mode='yes' ;; esac
      done
      if [ -n "$cursor_only" ]; then
        cursor="${STUB_GATE_LOG_CURSOR:-0,0,0,0}"
        for key in gate_out gate_err peer_out peer_err; do
          printf 'WRAPPER=GATE-LOG-CURSOR key=%s cursor=%s file=stub\n' "$key" "$cursor"
        done
        echo 'WRAPPER=OK verb=gate-log mode=cursor'
        exit 0
      fi
      # ROUND-5 M3: which STREAMS were actually read. `STUB_GATE_LOG_STREAMS`
      # is the space-separated set that answered; the default is both. A run
      # with only `peer` reproduces the real host condition where the gate
      # account home is absent and the peer-resolver log alone is readable.
      for key in gate_out gate_err; do
        case " ${STUB_GATE_LOG_STREAMS:-gate peer} " in
          *' gate '*) printf 'WRAPPER=GATE-LOG-READ key=%s state=read\n' "$key" ;;
          *) printf 'WRAPPER=GATE-LOG-READ key=%s state=absent\n' "$key" ;;
        esac
      done
      for key in peer_out peer_err; do
        case " ${STUB_GATE_LOG_STREAMS:-gate peer} " in
          *' peer '*) printf 'WRAPPER=GATE-LOG-READ key=%s state=read\n' "$key" ;;
          *) printf 'WRAPPER=GATE-LOG-READ key=%s state=absent\n' "$key" ;;
        esac
      done
      # Every per-stream verdict comes BEFORE this sentinel; everything after it
      # is log CONTENT, written by the gate service uid.
      echo 'WRAPPER=GATE-LOG-CONTENT-BEGIN'
      echo 'WRAPPER=GATE-LOG-BEGIN file=stub'
      if [ -n "$since_mode" ] && [ -n "${STUB_GATE_LOG_SINCE_BODY+x}" ]; then
        printf '%s\n' "$STUB_GATE_LOG_SINCE_BODY"
      else
        printf '%s\n' "${STUB_GATE_LOG_BODY:-}"
      fi
      echo 'WRAPPER=GATE-LOG-END file=stub'
      echo 'WRAPPER=OK verb=gate-log'
      exit 0
      ;;
    gate-port)
      # The verb that tells a probe where its own subject is. `STUB_GATE_PORT`
      # is the port; `absent` reproduces "no gate has published state" and
      # `refused` reproduces an unreadable one. `STUB_GATE_GENERATION` lets a
      # case rotate the generation mid-battery.
      case "${STUB_GATE_PORT:-49317}" in
        refused) echo 'WRAPPER=REJECT reason=unreadable gate runtime state' >&2; exit 20 ;;
        absent)  echo 'WRAPPER=GATE-PORT state=absent path=/stub/state.json'
                 echo 'WRAPPER=OK verb=gate-port state=absent'; exit 0 ;;
        *)
          gen="${STUB_GATE_GENERATION:-7}"
          if [ -n "${STUB_GATE_GENERATION_SEQ_FILE:-}" ]; then
            # Each call advances the generation, which is what a rotation
            # looks like from the outside: the port the request was aimed at
            # is not the port the current generation owns.
            gen="$(cat "$STUB_GATE_GENERATION_SEQ_FILE" 2>/dev/null || echo 1)"
            echo $((gen + 1)) > "$STUB_GATE_GENERATION_SEQ_FILE"
          fi
          printf 'WRAPPER=GATE-PORT state=present port=%s generation=%s agent_uid=%s path=/stub/state.json\n' \
            "${STUB_GATE_PORT:-49317}" "$gen" "$(id -u)"
          printf 'WRAPPER=OK verb=gate-port state=present port=%s generation=%s\n' \
            "${STUB_GATE_PORT:-49317}" "$gen"
          exit 0 ;;
      esac
      ;;
    arm)
      # A prompting arm, so `expect/arm-expect.exp` can be driven over a real
      # pty. `STUB_ARM_PROMPT` is the exact text the fake product asks.
      if [ -n "${STUB_ARM_PROMPT:-}" ]; then
        printf '%s' "$STUB_ARM_PROMPT"
        if read -r answer; then printf '\nARM_ANSWER=%s\n' "$answer"; else printf '\nARM_ANSWER=<eof>\n'; fi
      fi
      exit "${STUB_ARM_RC:-0}" ;;
    kickstart-daemons)
      # The verb answers in FOUR fields plus the observed arm state that
      # decided which absences were expected, and run-loop.sh records them
      # verbatim. `STUB_KICKSTART_SILENT` reproduces the one remaining way a
      # zero exit can still be untrustworthy: a run that exited 0 without ever
      # printing its own verdict.
      if [ "${STUB_KICKSTART_RC:-0}" -ne 0 ]; then
        printf 'WRAPPER=REJECT reason=kickstart failed for: stub-gate-daemon (arm_state=armed arm_basis=registry-names-uid restarted=stub-host-daemon absent_expected=- absent_unexpected=stub-gate-daemon restart_failed=-)\n'
        exit "$STUB_KICKSTART_RC"
      fi
      if [ -z "${STUB_KICKSTART_SILENT:-}" ]; then
        printf 'WRAPPER=OK verb=kickstart-daemons arm_state=%s arm_basis=%s restarted=stub-host-daemon absent_expected=%s absent_unexpected=- restart_failed=-\n' \
          "${STUB_KICKSTART_ARM_STATE:-not-armed}" \
          "${STUB_KICKSTART_ARM_BASIS:-registry-absent}" \
          "${STUB_KICKSTART_ABSENT_EXPECTED:-stub-gate-daemon}"
      fi
      exit 0 ;;
    mint)                    exit "${STUB_MINT_RC:-0}" ;;
    retire)                  exit "${STUB_RETIRE_RC:-0}" ;;
    unprotect|clean-markers) exit "${STUB_WRAPPER_RC:-0}" ;;
    *curl)
      if [ "${STUB_CURL:-ok}" = 'refused' ]; then
        echo 'sudo: a password is required' >&2
        exit 1
      fi
      # ROUND-5 B1. Whether this request was aimed at the GATE is now visible
      # to the tests: a `--proxy` argument is the only thing that makes a
      # request traverse the CONNECT gate, and a case can assert that P1's
      # requests carried one and P2's did not.
      via='direct'
      url=''
      for u in "${args[@]}"; do
        case "$u" in
          --proxy) via='gate' ;;
          https://*) url="$u" ;;
        esac
      done
      if [ -n "${STUB_CURL_LOG:-}" ]; then printf '%s %s\n' "$via" "$url" >> "$STUB_CURL_LOG"; fi
      # The BLOCKED endpoint answers with a denial, so a battery run's only
      # remaining problem can be the one the case is about.
      case "$url" in
        https://example.com) echo "${STUB_BLOCKED_CODE:-${STUB_CURL_CODE:-200}}"; exit 0 ;;
      esac
      echo "${STUB_CURL_CODE:-200}"; exit 0 ;;
  esac
done
exit 0
STUB
chmod +x "$STUBBIN/sudo"
LOOP_UUID='DC6E6D25-7885-5B37-948A-5C942737CFF4'
LOOP_FP="$(bash -c ". '$HERE/lib/rails.sh'; rails_host_fingerprint_of '$LOOP_UUID'")"
cat > "$STUBBIN/ioreg" <<STUB
#!/bin/bash
printf '%s\n' '    "IOPlatformUUID" = "$LOOP_UUID"'
STUB
chmod +x "$STUBBIN/ioreg"

# The sandbox harness: byte-identical drivers, with only fixture constants
# substituted so the tests can run without touching the real host state.
HARNESS="$SANDBOX/harness"
mkdir -p "$HARNESS/lib"
cp -R "$HERE/drivers" "$HARNESS/drivers"
cp "$HERE/lib/probe.sh" "$HARNESS/lib/probe.sh"
cp "$HERE/build-wrapper.sh" "$HARNESS/build-wrapper.sh"
cp "$HERE/wrapper-main.sh" "$HARNESS/wrapper-main.sh"
cp "$HERE/wrapper.sha256" "$HARNESS/wrapper.sha256"
LOOP_WRAPPER="$SANDBOX/fake-installed-wrapper"
: > "$LOOP_WRAPPER"
chmod +x "$LOOP_WRAPPER"
sed "s|^INSTALLED_WRAPPER=.*|INSTALLED_WRAPPER='$LOOP_WRAPPER'|" \
  "$HERE/drivers/run-loop.sh" > "$HARNESS/drivers/run-loop.sh"
chmod +x "$HARNESS/drivers/run-loop.sh"
sed -e "s|^RAILS_SYSTEM_BIN_DIRS='/usr/bin /bin /usr/sbin /sbin'\$|RAILS_SYSTEM_BIN_DIRS='$STUBBIN /usr/bin /bin /usr/sbin /sbin'|" \
  -e "s|^RAILS_DISPOSABLE_BASE=.*|RAILS_DISPOSABLE_BASE='$BASE'|" \
  -e "s|^RAILS_AGENT_ACCOUNT_ALLOW=.*|RAILS_AGENT_ACCOUNT_ALLOW='$ME'|" \
  -e "s|^RAILS_HOST_ALLOW_FP=.*|RAILS_HOST_ALLOW_FP='$LOOP_FP'|" \
  -e "s|^RAILS_HOST_DENY_FP=.*|RAILS_HOST_DENY_FP=''|" \
  -e "s|^RAILS_HOST_DENY=.*|RAILS_HOST_DENY=''|" \
  "$HERE/lib/rails.sh" > "$HARNESS/lib/rails.sh"
cat >> "$HARNESS/lib/rails.sh" <<'STUB'

# TEST ONLY: run-loop flow tests need to reach the ladder without installing a
# root-owned grant target. Production run-loop.sh still asserts the real
# integrity rail; the TypeScript structural suite pins that call site.
rails_assert_wrapper_integrity() { return 0; }
STUB
# A substitution that silently did not happen would leave this battery testing
# the real /usr/bin/sudo and reporting whatever that did. That is the same class
# as everything else in this file, so it is checked rather than assumed.
if grep -q "^RAILS_SYSTEM_BIN_DIRS='$STUBBIN " "$HARNESS/lib/rails.sh" &&
   grep -q "^RAILS_DISPOSABLE_BASE='$BASE'\$" "$HARNESS/lib/rails.sh"; then
  printf 'ok    the driver battery resolves its tools through the rails CONSTANT, not PATH\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL  *** the RAILS_SYSTEM_BIN_DIRS override did not apply; this battery would test nothing ***\n'
  FAIL=$((FAIL + 1))
fi

TD_EV="$SANDBOX/teardown-evidence"
run_teardown() {
  STUB_STORAGE="$LOOPDIR" "$HARNESS/drivers/teardown-verify.sh" \
    --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$(id -u)" \
    --evidence-dir "$TD_EV" --base "$BASE" --no-retire 2>&1
}

# THE BLOCKER-1 REGRESSION ITSELF. Same stub, same driver, reachable ONLY
# through PATH this time: the SHIPPED harness, whose resolver does not consult
# PATH. A planted `sudo` must produce NO observations at all.
printf '== a PATH-planted sudo cannot forge evidence (round-3 BLOCKER 1) ==\n'
PLANT_LOG="$SANDBOX/planted-sudo.log"
: > "$PLANT_LOG"
set +e   # declared exception: this run is EXPECTED to exit nonzero
planted_out="$(PATH="$STUBBIN:$PATH" STUB_SUDO_LOG="$PLANT_LOG" \
  STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 STUB_FORTRESS=ok \
  "$HERE/drivers/teardown-verify.sh" \
    --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$(id -u)" \
    --evidence-dir "$SANDBOX/planted-evidence" --base "$BASE" --no-retire 2>&1)"
planted_rc=$?
set -e
if [ -s "$PLANT_LOG" ]; then
  printf 'FAIL  *** the planted sudo on PATH was invoked; the drivers still resolve through PATH ***\n'
  note "log: $(cat "$PLANT_LOG")"
  FAIL=$((FAIL + 1))
else
  printf 'ok    the planted sudo on PATH was never invoked\n'
  PASS=$((PASS + 1))
fi
case "$planted_out" in
  *'VERIFY=CLEAN check=pf-anchor'*|*'VERIFY=CLEAN check=registry'*)
    printf 'FAIL  *** a PATH-planted sudo produced a CLEAN verdict; the round-3 BLOCKER is back ***\n'
    note "output: $planted_out"
    FAIL=$((FAIL + 1)) ;;
  *)
    if [ "$planted_rc" -ne 0 ]; then
      printf 'ok    a PATH-planted sudo produced no clean verdict and a nonzero exit (%s)\n' "$planted_rc"
      PASS=$((PASS + 1))
    else
      printf 'FAIL  a PATH-planted sudo run exited 0\n'
      note "output: $planted_out"
      FAIL=$((FAIL + 1))
    fi ;;
esac

set +e   # declared exception: these runs are EXPECTED to exit nonzero
out="$(STUB_PF=refused run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=UNOBSERVED check=pf-anchor'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    a pf anchor that could not be READ is UNOBSERVED, not clean (exit %s)\n' "$rc"
      PASS=$((PASS + 1))
    else
      printf 'FAIL  teardown-verify said UNOBSERVED but exited 0\n'
      FAIL=$((FAIL + 1))
    fi
    ;;
  *)
    printf 'FAIL  *** a refused pf read was not reported UNOBSERVED; the fail-open is back ***\n'
    note "output: $out"
    FAIL=$((FAIL + 1))
    ;;
esac

# --- THE REGISTRY, TRI-STATE (round-3 H1 / Codex finding 3) ---------------
#
# Three inputs, three DIFFERENT verdicts. The reviewed code collapsed all of
# them into "clean", and correcting the path alone would not have changed that:
# the real registry is root-0600, so an unprivileged read of it lands in exactly
# the same `else`.
set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 STUB_REGISTRY=refused run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=UNOBSERVED check=registry'*)
    printf 'ok    a registry that could not be READ is UNOBSERVED, not clean\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** an unreadable registry was not reported UNOBSERVED ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 \
       STUB_REGISTRY=present STUB_REGISTRY_BODY="{\"committed\":[{\"fortress\":\"$LOOPDIR\"}]}" \
       run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=DIRTY check=registry'*)
    printf 'ok    a registry still naming this fortress is DIRTY\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** an orphaned registry entry was not reported dirty ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 \
       STUB_REGISTRY=present STUB_REGISTRY_BODY='{"committed":[]}' run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=CLEAN check=registry read, and it does not reference this fortress'*)
    printf 'ok    a registry that WAS read and does not name this fortress is clean\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  a read, unrelated registry was not reported clean\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# ROUND-5 L2. The absent branch used to be decided by `^WRAPPER=REGISTRY-ABSENT`
# anywhere in the verb's combined output -- INCLUDING the content region, which
# carries the registry file's own bytes between REGISTRY-BEGIN and
# REGISTRY-END -- and that branch is evaluated BEFORE the dirty check. So a
# registry whose CONTENT contained that token short-circuited the check that
# would have found this fortress in it. The drivers now key on the verb's
# single-line verdict, which cannot appear inside content.
set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 \
       STUB_REGISTRY=present \
       STUB_REGISTRY_BODY="$(printf 'WRAPPER=REGISTRY-ABSENT path=/spoof\n{"committed":[{"fortress":"%s"}]}' "$LOOPDIR")" \
       run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=DIRTY check=registry'*)
    printf 'ok    an ABSENT token inside the registry CONTENT cannot short-circuit the dirty check\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** registry content forged the absent verdict and hid a live entry ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
# ...and the same attack with the CURRENT token, which is the version of this
# defect I shipped in my own first pass at L2. Renaming the token does not fix
# a check that reads a machine token out of a content region; reading the LAST
# verdict line does, because content is always printed BEFORE the verdict.
set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 \
       STUB_REGISTRY=present \
       STUB_REGISTRY_BODY="$(printf 'WRAPPER=OK verb=registry-state state=absent path=/spoof\n{"committed":[{"fortress":"%s"}]}' "$LOOPDIR")" \
       run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=DIRTY check=registry'*)
    printf 'ok    the CURRENT verdict token is not trusted from inside the content region either\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** registry content forged the CURRENT absent verdict and hid a live entry ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- THE FORTRESS, TRI-STATE ----------------------------------------------
set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 STUB_FORTRESS=refused run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=UNOBSERVED check=fortress-state'*)
    case "$out" in
      *'VERIFY=CLEAN check=marker'*|*'VERIFY=CLEAN check=locks'*)
        printf 'FAIL  *** a marker/lock check was CLEAN on a fortress that was never read ***\n'
        note "output: $out"; FAIL=$((FAIL + 1)) ;;
      *)
        printf 'ok    an unread fortress is ONE unobserved finding, not three clean ones\n'
        PASS=$((PASS + 1)) ;;
    esac ;;
  *)
    printf 'FAIL  *** an unread fortress was not reported UNOBSERVED ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 STUB_MARKER=present run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=DIRTY check=marker'*)
    printf 'ok    a marker that survived teardown is DIRTY\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  a surviving marker was not reported dirty\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 STUB_AUDIT_LOCK=present-empty run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=DIRTY check=locks'*)
    printf 'ok    a zero-length audit lock that survived teardown is DIRTY\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  a surviving zero-length lock was not reported dirty\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 run_teardown)"; rc=$?
set -e
if [ "$rc" -eq 0 ]; then
  case "$out" in
    *'VERIFY=CLEAN check=pf-anchor'*)
      printf 'ok    an empty pf anchor that WAS read is clean\n'; PASS=$((PASS + 1)) ;;
    *)
      printf 'FAIL  a readable empty pf anchor was not reported clean\n'
      note "output: $out"; FAIL=$((FAIL + 1)) ;;
  esac
else
  printf 'FAIL  the happy teardown path exited %s\n' "$rc"
  note "output: $out"
  FAIL=$((FAIL + 1))
fi

set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='block drop all' STUB_CURL_CODE=200 run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=DIRTY check=pf-anchor'*)
    printf 'ok    a pf anchor that still carries rules is DIRTY\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  a pf anchor with rules was not reported dirty\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE='000' run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=DIRTY check=agent-unconfined'*)
    printf 'ok    an agent that cannot reach the network after teardown is DIRTY\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  a still-confined agent was not reported dirty\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# AN UNREADABLE FORTRESS IS NOT AN EMPTY ONE.
#
# The marker and lock checks read ABSENCE as CLEAN, and a directory this
# process cannot traverse looks exactly like a directory with nothing left in
# it. This is live, not hypothetical: `tightenStoragePermissions` chmods the
# whole fortress to 0700 on every server start, and the disposable fortress is
# ROOT-owned. Root reads it through `fortress-state` now, but the driver still
# has to RESOLVE the path, and the storage rail's own `cd -P` post-condition is
# what stops it hard when it cannot even traverse there.
chmod 0000 "$LOOPDIR"
set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 run_teardown)"; rc=$?
set -e
chmod 0755 "$LOOPDIR"
if [ "$rc" -ne 0 ]; then
  printf 'ok    an unreadable fortress is a loud nonzero stop (exit %s)\n' "$rc"
  PASS=$((PASS + 1))
else
  printf 'FAIL  *** an unreadable fortress exited 0 ***\n'
  note "output: $out"
  FAIL=$((FAIL + 1))
fi
case "$out" in
  *'VERIFY=CLEAN check=marker'*|*'VERIFY=CLEAN check=locks'*)
    printf 'FAIL  *** a marker/lock check reported CLEAN on a fortress it could not read ***\n'
    note "output: $out"
    FAIL=$((FAIL + 1)) ;;
  *)
    printf 'ok    no absence-means-clean verdict was drawn from what could not be seen\n'
    PASS=$((PASS + 1)) ;;
esac

# The OTHER half, which is a different branch: the as-agent probe could not be
# RUN at all, because `sudo -n -u <agent>` is not covered by the reviewed grant.
# "Could not observe" must be DIRTY and must say so, not be folded into "still
# confined" and not be read as clean.
set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL=refused run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=UNOBSERVED check=agent-unconfined reason=could not RUN the as-agent probe'*)
    printf 'ok    an as-agent probe that could not RUN is UNOBSERVED, and says which\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  a probe that could not run was not reported as unobservable\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- RETIREMENT (round-3 M1) ----------------------------------------------
set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 \
       STUB_STORAGE="$LOOPDIR" "$HARNESS/drivers/teardown-verify.sh" \
         --run-id 'good1' --operator-account "$ME" \
         --agent-account "$ME" --agent-uid "$(id -u)" \
         --evidence-dir "$TD_EV" --base "$BASE" 2>&1)"; rc=$?
set -e
case "$out" in
  *'VERIFY=CLEAN check=retire'*)
    printf 'ok    teardown retires the disposable fortress by default\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  teardown did not retire the disposable fortress\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
set +e   # declared exception
out="$(STUB_PF=ok STUB_PF_RULES='' STUB_CURL_CODE=200 STUB_RETIRE_RC=1 \
       STUB_STORAGE="$LOOPDIR" "$HARNESS/drivers/teardown-verify.sh" \
         --run-id 'good1' --operator-account "$ME" \
         --agent-account "$ME" --agent-uid "$(id -u)" \
         --evidence-dir "$TD_EV" --base "$BASE" 2>&1)"; rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  case "$out" in
    *'VERIFY=DIRTY check=retire'*)
      printf 'ok    a fortress that could not be retired stops the night\n'; PASS=$((PASS + 1)) ;;
    *)
      printf 'FAIL  a failed retire was not reported dirty\n'
      note "output: $out"; FAIL=$((FAIL + 1)) ;;
  esac
else
  printf 'FAIL  a failed retire exited 0\n'
  note "output: $out"; FAIL=$((FAIL + 1))
fi

# --- PREFLIGHT: A CHECK THAT OBSERVED NOTHING HAS NOT PASSED --------------
#
# Three checks in this file reported PASS having measured nothing (round-3 H1):
# `orphan-registry` watched a path the product does not use, `plist-absolute-node`
# passed when its entire input set was absent, and the marker/lock checks read a
# fortress the process is not allowed to look inside.
printf '== preflight: a check that observed nothing has not passed ==\n'
PF_EV="$SANDBOX/preflight-evidence"
mkdir -p "$PF_EV"
run_preflight() {
  STUB_STORAGE="$LOOPDIR" "$HARNESS/drivers/preflight.sh" \
    --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$(id -u)" \
    --base "$BASE" 2>&1
}
set +e   # declared exception: preflight is EXPECTED to fail on a non-drill host
out="$(run_preflight)"; rc=$?
set -e
# The D9 layer: no plist to screen is a FAILURE, not an empty success.
case "$out" in
  *'PREFLIGHT=FAIL check=plist-absolute-node'*'no plist to screen'*)
    printf 'ok    an absent plist set FAILS the D9 check instead of passing it\n'
    PASS=$((PASS + 1)) ;;
  *'PREFLIGHT=PASS check=plist-absolute-node'*)
    printf 'FAIL  *** the D9 check PASSED having screened nothing ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
  *)
    printf 'FAIL  the D9 check produced no recognizable verdict\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
# The labels it looks for are the PRODUCT's, per confined uid.
case "$out" in
  *"daemon-dist-ai.sanctuaryprotocol.egress-gate.$(id -u)"*)
    printf 'ok    preflight screens the product per-uid daemon labels\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** preflight is not using the product daemon labels ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
set +e   # declared exception
out="$(STUB_REGISTRY=refused run_preflight)"; rc=$?
set -e
case "$out" in
  *'PREFLIGHT=FAIL check=orphan-registry'*'could not READ'*)
    printf 'ok    a registry that could not be READ FAILS preflight\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** an unreadable registry did not fail preflight ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
set +e   # declared exception
out="$(STUB_FORTRESS=refused run_preflight)"; rc=$?
set -e
case "$out" in
  *'PREFLIGHT=PASS check=stale-marker'*|*'PREFLIGHT=PASS check=zero-byte-lock'*)
    printf 'FAIL  *** an absence-means-good check PASSED on a fortress never read ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
  *'PREFLIGHT=FAIL check=fortress-state'*)
    printf 'ok    an unread fortress is ONE preflight failure, not two passes\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  an unread fortress produced no recognizable preflight verdict\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
set +e   # declared exception
out="$(STUB_AUDIT_LOCK=present-empty run_preflight)"; rc=$?
set -e
case "$out" in
  *'PREFLIGHT=FAIL check=zero-byte-lock'*)
    printf 'ok    a zero-length audit lock is caught before an iteration starts\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** a zero-byte lock was not caught ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- RUN-LOOP: EARLY FAILURES STILL RETIRE THE DISPOSABLE FORTRESS --------
printf '== run-loop: early failures retire the disposable fortress ==\n'
run_loop_once() {
  local root="$1" sudo_log="${2:-}" kickstart_rc="${3:-}" mint_rc="${4:-}" retire_rc="${5:-}"
  mkdir -p "$root/home"
  STUB_SUDO_LOG="$sudo_log" \
  STUB_KICKSTART_RC="$kickstart_rc" \
  STUB_MINT_RC="$mint_rc" \
  STUB_RETIRE_RC="$retire_rc" \
  "$HARNESS/drivers/run-loop.sh" --mode sweep --iterations 1 \
    --operator-account "$ME" --agent-account "$ME" --agent-uid "$(id -u)" \
    --evidence-root "$root/evidence" --build-sha test-sha --home "$root/home" 2>&1
}

KICK_LOOP="$SANDBOX/loop-kickstart"
KICK_SUDO_LOG="$SANDBOX/loop-kickstart-sudo.log"
set +e   # declared exception
out="$(run_loop_once "$KICK_LOOP" "$KICK_SUDO_LOG" 7 '' '')"; rc=$?
set -e
kick_findings="$(cat "$KICK_LOOP/evidence/FINDINGS.jsonl" 2>/dev/null || true)"
case "$(cat "$KICK_SUDO_LOG" 2>/dev/null || true):$kick_findings:$out" in
  *kickstart-daemons*retire*'"step":"kickstart","result":"FAIL"'*'"step":"retire","result":"PASS"'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    a kickstart failure runs retire before the iteration exits\n'
      PASS=$((PASS + 1))
    else
      printf 'FAIL  kickstart failed and retired, but run-loop exited 0\n'
      note "output: $out"; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  *** a kickstart failure did not run and record retire ***\n'
    note "sudo log: $(cat "$KICK_SUDO_LOG" 2>/dev/null || true)"
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# The loop must record what the verb SAID, not what the loop hoped. Before the
# 2026-07-25 live finding this step's PASS text was the fixed string 'gate and
# resolver daemons restarted on the current dist' -- which was a claim about
# two daemons that, on the host it was written for, did not exist.
KICKOK_LOOP="$SANDBOX/loop-kickstart-ok"
KICKOK_SUDO_LOG="$SANDBOX/loop-kickstart-ok-sudo.log"
set +e   # declared exception: preflight still fails on a non-drill host
out="$(run_loop_once "$KICKOK_LOOP" "$KICKOK_SUDO_LOG" '' '' '')"; rc=$?
set -e
kickok_findings="$(cat "$KICKOK_LOOP/evidence/FINDINGS.jsonl" 2>/dev/null || true)"
case "$kickok_findings" in
  *'"step":"kickstart","result":"PASS"'*'arm_state=not-armed'*'absent_expected=stub-gate-daemon'*)
    printf 'ok    the kickstart finding carries the verb OWN four-field account, absent-expected included\n'
    PASS=$((PASS + 1)) ;;
  *'"step":"kickstart","result":"PASS"'*)
    printf 'FAIL  *** the kickstart PASS said more than the verb did: no restarted/absent breakdown ***\n'
    note "findings: $kickok_findings"; FAIL=$((FAIL + 1)) ;;
  *)
    printf 'FAIL  a successful kickstart produced no PASS finding\n'
    note "findings: $kickok_findings"; FAIL=$((FAIL + 1)) ;;
esac

# A zero exit with no verdict line is the same shape as an OK dump that observed
# nothing: it must not be read as a successful restart.
KICKSILENT_LOOP="$SANDBOX/loop-kickstart-silent"
mkdir -p "$KICKSILENT_LOOP/home"
set +e   # declared exception
out="$(STUB_KICKSTART_SILENT=yes "$HARNESS/drivers/run-loop.sh" --mode sweep --iterations 1 \
  --operator-account "$ME" --agent-account "$ME" --agent-uid "$(id -u)" \
  --evidence-root "$KICKSILENT_LOOP/evidence" --build-sha test-sha \
  --home "$KICKSILENT_LOOP/home" 2>&1)"; rc=$?
set -e
silent_findings="$(cat "$KICKSILENT_LOOP/evidence/FINDINGS.jsonl" 2>/dev/null || true)"
case "$silent_findings" in
  *'"step":"kickstart","result":"FAIL"'*'without its verdict line'*)
    printf 'ok    a kickstart that exited 0 without saying what it restarted is not a PASS\n'
    PASS=$((PASS + 1)) ;;
  *'"step":"kickstart","result":"PASS"'*)
    printf 'FAIL  *** a silent zero exit was recorded as daemons restarted ***\n'
    note "findings: $silent_findings"; FAIL=$((FAIL + 1)) ;;
  *)
    printf 'FAIL  a silent kickstart produced no recognizable finding\n'
    note "findings: $silent_findings"; FAIL=$((FAIL + 1)) ;;
esac

PREFLIGHT_LOOP="$SANDBOX/loop-preflight"
PREFLIGHT_SUDO_LOG="$SANDBOX/loop-preflight-sudo.log"
set +e   # declared exception
out="$(run_loop_once "$PREFLIGHT_LOOP" "$PREFLIGHT_SUDO_LOG" '' '' '')"; rc=$?
set -e
preflight_findings="$(cat "$PREFLIGHT_LOOP/evidence/FINDINGS.jsonl" 2>/dev/null || true)"
case "$(cat "$PREFLIGHT_SUDO_LOG" 2>/dev/null || true):$preflight_findings:$out" in
  *kickstart-daemons*mint*retire*'"step":"preflight","result":"FAIL"'*'"step":"retire","result":"PASS"'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    a preflight failure retires the minted disposable fortress\n'
      PASS=$((PASS + 1))
    else
      printf 'FAIL  preflight failed and retired, but run-loop exited 0\n'
      note "output: $out"; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  *** a preflight failure did not run and record retire ***\n'
    note "sudo log: $(cat "$PREFLIGHT_SUDO_LOG" 2>/dev/null || true)"
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# ROUND-5 L1. The MINT-failure retire path was the one of the three that no
# case covered: neutralising its `retire_iteration` call left the whole
# selftest green, so the "early failures retire the fortress" claim was proven
# for kickstart and preflight and merely asserted for mint. A test that passes
# whether or not the fix is present is not a proof.
MINT_LOOP="$SANDBOX/loop-mint"
MINT_SUDO_LOG="$SANDBOX/loop-mint-sudo.log"
set +e   # declared exception
out="$(run_loop_once "$MINT_LOOP" "$MINT_SUDO_LOG" '' 5 '')"; rc=$?
set -e
mint_findings="$(cat "$MINT_LOOP/evidence/FINDINGS.jsonl" 2>/dev/null || true)"
case "$mint_findings:$out" in
  *'"step":"mint","result":"FAIL"'*'"step":"retire","result":"PASS"'*'mint-failure'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    a MINT failure retires the disposable fortress before the iteration exits\n'
      PASS=$((PASS + 1))
    else
      printf 'FAIL  mint failed and retired, but run-loop exited 0\n'
      note "output: $out"; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  *** a mint failure did not run and record retire ***\n'
    note "sudo log: $(cat "$MINT_SUDO_LOG" 2>/dev/null || true)"
    note "findings: $mint_findings"
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# ROUND-5 L3. Every other rail call in run-loop.sh is wrapped in `( ... ) ||
# rail_stop` precisely because `rails__die` calls `exit`; the LOCK call was
# not, so a lock rejection exited 20 before the machine-readable `LOOP=STOP`
# token could be printed. It failed closed and it failed SILENTLY, and silent
# is the one thing a morning read cannot work with.
LOCK_LOOP="$SANDBOX/loop-locked"
mkdir -p "$LOCK_LOOP/home"
mkdir -p "$LOCK_LOOP/home/.sanctuary-drill-loop.lock"
printf '%s\n' "$$" > "$LOCK_LOOP/home/.sanctuary-drill-loop.lock/pid"
set +e   # declared exception
out="$("$HARNESS/drivers/run-loop.sh" --mode sweep --iterations 1 \
  --operator-account "$ME" --agent-account "$ME" --agent-uid "$(id -u)" \
  --evidence-root "$LOCK_LOOP/evidence" --build-sha test-sha --home "$LOCK_LOOP/home" 2>&1)"; rc=$?
set -e
case "$out" in
  *'LOOP=STOP reason=safety-rail'*'loop lock'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    a live loop lock stops the night with the LOOP=STOP token (exit %s)\n' "$rc"
      PASS=$((PASS + 1))
    else
      printf 'FAIL  a lock rejection printed LOOP=STOP and exited 0\n'
      note "output: $out"; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  *** a lock rejection exited without the LOOP=STOP token ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
rm -rf "$LOCK_LOOP/home/.sanctuary-drill-loop.lock"

DIRTY_LOOP="$SANDBOX/loop-retire-dirty"
DIRTY_SUDO_LOG="$SANDBOX/loop-retire-dirty-sudo.log"
set +e   # declared exception
out="$(run_loop_once "$DIRTY_LOOP" "$DIRTY_SUDO_LOG" 7 '' 9)"; rc=$?
set -e
dirty_findings="$(cat "$DIRTY_LOOP/evidence/FINDINGS.jsonl" 2>/dev/null || true)"
case "$dirty_findings:$out" in
  *'"step":"retire","result":"FAIL"'*'retire-after-kickstart'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    an early retire failure is a dirty stop, not a silent leftover\n'
      PASS=$((PASS + 1))
    else
      printf 'FAIL  retire failed but run-loop exited 0\n'
      note "output: $out"; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  *** failed early retire was not recorded as a dirty stop ***\n'
    note "sudo log: $(cat "$DIRTY_SUDO_LOG" 2>/dev/null || true)"
    note "findings: $dirty_findings"
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- ROUND-5 M4: the arm driver answers ONLY the question it was designed for
#
# THIS IS A SAFETY CASE, NOT A CORRECTNESS ONE. The generic branch in
# `arm-expect.exp` matched `(?i)\(y/n\)|\[y/N\]|continue\?` and answered `y`,
# an unbounded number of times, while driving a ROOT-run operation whose
# effects are HOST-WIDE: the pf anchor, the LaunchDaemons, the gate service
# account. A future product prompt of the shape "a gate is already armed for
# uid N; tear it down? (y/n)" would have got an unattended `y` on a machine
# that may be running something else entirely.
printf '== arm-expect answers ONLY the prompt the drill expects ==\n'
if command -v expect >/dev/null 2>&1; then
  ARM_STUB_WRAPPER="$SANDBOX/fake-arm-wrapper"
  : > "$ARM_STUB_WRAPPER"
  chmod +x "$ARM_STUB_WRAPPER"
  run_arm_expect() {
    PATH="$STUBBIN:$PATH" STUB_ARM_PROMPT="$1" \
      "$HERE/expect/arm-expect.exp" "$ARM_STUB_WRAPPER" 'good1' "$ME" "$ME" "$(id -u)" 2>&1
  }
  set +e   # declared exception
  out="$(run_arm_expect 'Proceed with account creation and arming? [y/N] ')"; rc=$?
  set -e
  case "$out:$rc" in
    *'ARM_ANSWER=y'*:0)
      printf 'ok    the ONE expected arm confirmation is answered\n'; PASS=$((PASS + 1)) ;;
    *)
      printf 'FAIL  *** the expected arm confirmation was not answered (rc=%s) ***\n' "$rc"
      note "output: $out"; FAIL=$((FAIL + 1)) ;;
  esac
  set +e   # declared exception: this run is EXPECTED to exit nonzero
  out="$(run_arm_expect 'a gate is already armed for uid 501; tear it down? (y/n) ')"; rc=$?
  set -e
  case "$out" in
    *'ARM_ANSWER=y'*)
      printf 'FAIL  *** an UNRECOGNISED root-run host-wide prompt was answered YES ***\n'
      note "output: $out"; FAIL=$((FAIL + 1)) ;;
    *)
      if [ "$rc" -ne 0 ]; then
        printf 'ok    an unrecognised confirmation prompt is refused, not consented to (exit %s)\n' "$rc"
        PASS=$((PASS + 1))
      else
        printf 'FAIL  an unrecognised prompt went unanswered but the driver exited 0\n'
        note "output: $out"; FAIL=$((FAIL + 1))
      fi ;;
  esac
  case "$out" in
    *'UNRECOGNISED confirmation prompt'*'tear it down'*)
      printf 'ok    and the refusal names the prompt it saw\n'; PASS=$((PASS + 1)) ;;
    *)
      printf 'FAIL  the refusal did not record which prompt appeared\n'
      note "output: $out"; FAIL=$((FAIL + 1)) ;;
  esac
else
  printf 'SKIP  expect is not installed; the arm-driver prompt cases cannot run here\n'
  SKIPPED=$((SKIPPED + 1))
fi

# --- THE PROBE BATTERY: A VERDICT MAY NOT OUTRUN ITS OBSERVATION ---------
#
# Round 3 (Codex finding 2): the battery reported `N3 SKIP`, left FAILED at
# zero, exited 0, and the loop wrote `"result":"PASS"` for the whole probe
# step. Two independent things have to be true before that can happen: exit 0
# AND `verified=yes`.
#
# Round 6 adds the class underneath it. Every case below drives the REAL
# battery through the REAL stub wrapper and asserts a property of the LEDGER,
# not of one probe's wording.
printf '== the probe battery: a skipped probe cannot become a pass ==\n'
PB_EV="$SANDBOX/probe-evidence"
run_probes() {
  STUB_STORAGE="$LOOPDIR" "$HARNESS/drivers/run-probe-battery.sh" \
    --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$(id -u)" \
    --evidence-dir "$PB_EV" --base "$BASE" --repeats 1 2>&1
}
set +e   # declared exception
out="$(STUB_GATE_LOG=refused STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 run_probes)"; rc=$?
set -e
case "$out" in
  *'verified=no'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    an unreadable gate log makes the battery verified=no and exit %s\n' "$rc"
      PASS=$((PASS + 1))
    else
      printf 'FAIL  *** the battery said verified=no and exited 0 ***\n'
      note "output: $out"; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  *** a battery that could not read the gate log did not say verified=no ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
case "$out" in
  *'PROBE=SUMMARY'*'skipped='*'P1-reason'*)
    printf 'ok    the summary NAMES the probes that did not run\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  the summary did not name the skipped probes\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
# And the round-4 N3 rule: a wrong-uid request that SUCCEEDED is a FAIL before
# the log reason is even considered. Stale or even current-looking
# peer_uid_mismatch text cannot turn an allowed request into a passing denial.
PB_CURL_LOG="$SANDBOX/probe-curl.log"
: > "$PB_CURL_LOG"
set +e   # declared exception
out="$(STUB_GATE_LOG=ok STUB_CURL_LOG="$PB_CURL_LOG" STUB_GATE_LOG_BODY="peer=$(id -u) allowlist peer_uid_mismatch" STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 run_probes)"; rc=$?
set -e
case "$out" in
  *'PROBE=N3 RESULT=FAIL'*'SUCCEEDED with code 200'*)
    printf 'ok    a wrong-uid request that SUCCEEDED is N3 FAIL, never stale-log PASS\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** a successful wrong-uid request was not a loud N3 FAIL ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
# ...and the reason half now produces evidence at all, which it structurally
# could not before (round-3 M5: it read a path nothing writes).
case "$out" in
  *'PROBE=P1-reason RESULT=PASS'*)
    printf 'ok    the reason half of the ladder can now actually be evaluated\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  the reason half still produced no verdict from a readable gate log\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- ROUND-5 B1: the requests actually go THROUGH THE GATE ----------------
#
# The blocker in one sentence: `P1` printed `RESULT=PASS "allowed endpoints
# reachable through the gate"` for a bare `curl` that had no `--proxy` and
# could not have had one, because the harness had no way to learn the gate
# port. The stub now records the CHANNEL of every request it serves, so this
# is measured rather than reasoned about.
case "$out" in
  *'PROBE=P1 RESULT=PASS'*'channels=gate'*'through the gate'*)
    printf 'ok    P1 claims through-gate reachability on a through-gate basis\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** P1 did not report a through-gate PASS on a gate channel ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
if grep -q '^gate https://api\.venice\.ai' "$PB_CURL_LOG" 2>/dev/null; then
  printf 'ok    the P1 requests carried a --proxy at the gate port\n'; PASS=$((PASS + 1))
else
  printf 'FAIL  *** no request was ever aimed at the gate; the round-5 B1 defect is back ***\n'
  note "curl log: $(cat "$PB_CURL_LOG" 2>/dev/null || true)"; FAIL=$((FAIL + 1))
fi
# P2 is the OTHER half of the differential and it must be DIRECT. If P2 went
# through the gate it would be asking N3's question, and the two probes were
# mutually contradictory as written precisely because the channel was not
# represented anywhere.
if grep -q '^direct https://example\.com' "$PB_CURL_LOG" 2>/dev/null; then
  printf 'ok    the P2 differential request was made DIRECTLY, not through the gate\n'
  PASS=$((PASS + 1))
else
  printf 'FAIL  *** P2 did not make a direct request; the per-uid differential measures nothing ***\n'
  note "curl log: $(cat "$PB_CURL_LOG" 2>/dev/null || true)"; FAIL=$((FAIL + 1))
fi
# N3's wrong-uid request must go TO THE GATE PORT. `peer_uid_mismatch` is only
# ever emitted for a socket connected to the gate, so a direct wrong-uid
# request cannot produce the event the probe exists to observe.
n3_channel="$(printf '%s\n' "$out" | grep -m1 '^PROBE=N3 ' || printf '')"
case "$n3_channel" in
  *'channels=gate'*)
    printf 'ok    the N3 wrong-uid request was aimed at the gate port\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** N3 measured something other than a request to the gate ***\n'
    note "line: $n3_channel"; FAIL=$((FAIL + 1)) ;;
esac
# THE LEDGER INVARIANT, asserted over the whole run rather than probe by probe.
if printf '%s\n' "$out" | grep -q 'RESULT=PASS.*observed=0'; then
  printf 'FAIL  *** a PASS was emitted with ZERO observations behind it ***\n'
  note "output: $out"; FAIL=$((FAIL + 1))
else
  printf 'ok    no PASS in the run was emitted with zero observations\n'; PASS=$((PASS + 1))
fi
# ROUND-5 M2: N3's verdict is bound to N3's OWN request. It used to read a
# `$code` last written by the N1 loop. Every basis id names the probe that
# recorded it, and `report` refuses a cross-probe basis, so this asserts the
# binding on real output.
n3_basis_ids="$(printf '%s\n' "$n3_channel" | sed -e 's/.*basis=\([^ ]*\).*/\1/' | tr ',' ' ')"
n3_bad=0
for oid in $n3_basis_ids; do
  case "$oid" in -|'') continue ;; esac
  if ! grep -q "^$oid	N3	" "$PB_EV/observations.tsv"; then n3_bad=1; fi
done
if [ "$n3_bad" -eq 0 ] && [ -n "$n3_basis_ids" ]; then
  printf 'ok    every observation N3 cited was recorded BY N3\n'; PASS=$((PASS + 1))
else
  printf 'FAIL  *** N3 cited an observation it did not make ***\n'
  note "basis: $n3_basis_ids"; FAIL=$((FAIL + 1))
fi

# --- ROUND-5 B1, the negative: no gate port means no through-gate claim ---
set +e   # declared exception
out="$(STUB_GATE_PORT=absent STUB_GATE_LOG=ok STUB_GATE_LOG_BODY="peer=$(id -u) allowlist" STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 run_probes)"; rc=$?
set -e
if printf '%s\n' "$out" | grep -q 'RESULT=PASS.*through the gate'; then
  printf 'FAIL  *** a through-gate PASS was printed with NO gate port to aim at ***\n'
  note "output: $out"; FAIL=$((FAIL + 1))
else
  printf 'ok    with no gate port, nothing claims through-gate reachability\n'; PASS=$((PASS + 1))
fi
case "$out:$rc" in
  *'PROBE=P1 RESULT=UNOBSERVED'*'verified=no'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    an unlearnable gate port makes P1 UNOBSERVED and the battery nonzero\n'
      PASS=$((PASS + 1))
    else
      printf 'FAIL  the battery was UNOBSERVED and exited 0\n'; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  *** an unlearnable gate port did not make P1 UNOBSERVED ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- a generation that ROTATES across a request is not attributable -------
#
# "assert the port used was the port the CURRENT generation committed". The
# stub advances the generation on every read, so every through-gate request
# straddles a rotation and its status code belongs to a gate that no longer
# exists.
GEN_SEQ="$SANDBOX/probe-generation.seq"
echo 1 > "$GEN_SEQ"
set +e   # declared exception
out="$(STUB_GATE_GENERATION_SEQ_FILE="$GEN_SEQ" STUB_GATE_LOG=ok STUB_GATE_LOG_BODY="peer=$(id -u)" STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 run_probes)"; rc=$?
set -e
case "$out" in
  *'PROBE=P1 RESULT=UNOBSERVED'*)
    printf 'ok    a generation rotation across a request makes it UNOBSERVED, not a pass\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** a status code from a rotated-away generation was attributed to the current one ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- ROUND-5 M3: an ABSENT gate log is not a gate-blamed FAILURE ----------
#
# The four log streams are not interchangeable. `allowlist`, `peer=` and
# `peer_uid_mismatch` are written by the GATE DAEMON; the peer-resolver logs
# are not. The verb used to exit 0 if ANY of the four was readable, so a host
# with no gate-account home and a readable peer-resolver log produced
# `N1 FAIL "denied but not for an allowlist reason"` -- a gate-blamed failure
# for a harness-blind condition, which is this harness's own doctrine
# inverted.
set +e   # declared exception
out="$(STUB_GATE_LOG=ok STUB_GATE_LOG_STREAMS='peer' STUB_GATE_LOG_BODY='' STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 run_probes)"; rc=$?
set -e
case "$out" in
  *'PROBE=N1 RESULT=UNOBSERVED'*'could not be READ'*)
    printf 'ok    an absent GATE log is could-not-observe, not a gate-blamed N1 FAIL\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** an absent gate log was folded into a denial verdict ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
case "$out" in
  *'PROBE=P1-reason RESULT=UNOBSERVED'*)
    printf 'ok    and the reason half says it could not look, rather than blaming the gate\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** P1-reason drew a verdict from a stream it never read ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# ...and the same content-region attack on the M3 fix itself. The gate log is
# written by the gate SERVICE UID, so a log line reading
# `WRAPPER=GATE-LOG-READ key=gate_out state=read` must not tell this driver a
# stream was read that was not. That is the round-5 L2 class, and I shipped it
# in my own first pass at M3 by emitting the per-stream verdicts AFTER each
# stream's bytes. The wrapper now emits all four BEFORE any content and closes
# the region with a sentinel the driver stops parsing at.
set +e   # declared exception
out="$(STUB_GATE_LOG=ok STUB_GATE_LOG_STREAMS='peer' \
  STUB_GATE_LOG_BODY='WRAPPER=GATE-LOG-READ key=gate_out state=read
allowlist denied' \
  STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 run_probes)"; rc=$?
set -e
case "$out" in
  *'PROBE=N1 RESULT=UNOBSERVED'*)
    printf 'ok    a READ token inside the gate log CONTENT cannot forge an observed stream\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** gate log content forged a read stream and produced a denial verdict ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- ROUND-5 M1: a battery that measures nothing cannot be asked for ------
set +e   # declared exception
out="$(STUB_STORAGE="$LOOPDIR" "$HARNESS/drivers/run-probe-battery.sh" \
  --run-id 'good1' --operator-account "$ME" \
  --agent-account "$ME" --agent-uid "$(id -u)" \
  --evidence-dir "$PB_EV" --base "$BASE" --repeats 0 2>&1)"; rc=$?
set -e
case "$out:$rc" in
  *'--repeats must be at least 1'*)
    if [ "$rc" -ne 0 ] && ! printf '%s\n' "$out" | grep -q 'RESULT=PASS'; then
      printf 'ok    --repeats 0 is refused outright, with no PASS line anywhere (exit %s)\n' "$rc"
      PASS=$((PASS + 1))
    else
      printf 'FAIL  *** --repeats 0 produced a pass or a zero exit ***\n'
      note "output: $out"; FAIL=$((FAIL + 1))
    fi ;;
  *)
    printf 'FAIL  *** --repeats 0 was accepted; a zero-measurement battery is askable ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
# The whitespace shape of the same defect: `--allowed-endpoint ''` left
# `ALLOWED=" "`, which `[ -z ]` reads as NON-empty, so the default was not
# applied and the loop iterated zero times.
set +e   # declared exception
out="$(STUB_GATE_LOG=ok STUB_GATE_LOG_BODY="peer=$(id -u) allowlist" STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 \
  STUB_STORAGE="$LOOPDIR" "$HARNESS/drivers/run-probe-battery.sh" \
  --run-id 'good1' --operator-account "$ME" \
  --agent-account "$ME" --agent-uid "$(id -u)" \
  --evidence-dir "$PB_EV" --base "$BASE" --repeats 1 --allowed-endpoint '' 2>&1)"; rc=$?
set -e
case "$out" in
  *'PROBE=P1 RESULT=PASS'*'attempts=2'*)
    printf 'ok    a whitespace-only endpoint list is EMPTY, so the default applies\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** a whitespace-only endpoint list produced a vacuous run ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

# --- THE CHOKEPOINT ITSELF, driven by DELIBERATELY DEFECTIVE callers ------
#
# The four cases above prove the battery as written is honest. These prove the
# LEDGER refuses a dishonest one, which is the property that has to survive the
# next edit. Each injects one instance of the class into a byte-identical copy
# of the battery and asserts the verdict is refused, counted as a HARNESS
# DEFECT, and cannot be read as green.
printf '== the ledger refuses a verdict the observations do not support ==\n'
inject_defect() {
  # inject_defect <name> <sed-expr> <marker-that-must-appear-after>
  local name="$1" expr="$2" marker="$3" dst="$HARNESS/drivers/run-probe-battery-$1.sh"
  sed -e "$expr" "$HARNESS/drivers/run-probe-battery.sh" > "$dst"
  chmod +x "$dst"
  # A substitution that silently did not happen would leave this case testing
  # the UNMODIFIED battery and reporting a pass for nothing. Same discipline as
  # the RAILS_SYSTEM_BIN_DIRS check above.
  if ! grep -q -F -- "$marker" "$dst"; then
    printf 'FAIL  *** the %s injection did not apply; this case would test nothing ***\n' "$name"
    FAIL=$((FAIL + 1))
    return 1
  fi
  return 0
}
run_defect() {
  STUB_GATE_LOG=ok STUB_GATE_LOG_BODY="peer=$(id -u) allowlist peer_uid_mismatch" \
  STUB_GATE_PORT="${DEFECT_GATE_PORT:-49317}" \
  STUB_CURL_CODE=200 STUB_BLOCKED_CODE="${DEFECT_BLOCKED_CODE:-403}" STUB_STORAGE="$LOOPDIR" \
    "$HARNESS/drivers/run-probe-battery-$1.sh" \
    --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$(id -u)" \
    --evidence-dir "$SANDBOX/probe-defect-$1" --base "$BASE" --repeats 1 2>&1
}
assert_defect_refused() {
  local name="$1" what="$2" out rc
  set +e
  out="$(run_defect "$name")"; rc=$?
  set -e
  case "$out:$rc" in
    *'HARNESS DEFECT'*'defects=1'*'verified=no'*)
      if [ "$rc" -eq 4 ]; then
        printf 'ok    %s\n' "$what"; PASS=$((PASS + 1))
      else
        printf 'FAIL  %s: refused but exited %s, not 4\n' "$what" "$rc"
        note "output: $out"; FAIL=$((FAIL + 1))
      fi ;;
    *)
      printf 'FAIL  *** %s: the ledger let it through ***\n' "$what"
      note "output: $out"; FAIL=$((FAIL + 1)) ;;
  esac
}
# (a) zero measurements. This is round-5 M1 at the seam rather than at the
#     argument: even if a probe loop somehow runs zero times, it cannot pass.
if inject_defect zerobasis \
  's|report P1 PASS "${p1_basis#,}"|report P1 PASS ""|' \
  'report P1 PASS ""'
then
  assert_defect_refused zerobasis 'a PASS with an EMPTY basis is refused as a harness defect'
fi
# (b) another probe's observation. `obs1` is P1's first through-gate request,
#     so this is P2 passing on P1's evidence. The target is P2 deliberately:
#     its verdict text names no mechanism, so OWNERSHIP is the only thing that
#     can catch it and the case isolates that check instead of being defended
#     by the claim guard as well.
if inject_defect crossprobe \
  's|report P2-operator PASS "${p2_basis#,}"|report P2-operator PASS "obs1"|' \
  'report P2-operator PASS "obs1"'
then
  DEFECT_BLOCKED_CODE=200 \
    assert_defect_refused crossprobe "a PASS citing ANOTHER probe's observation is refused"
fi
# (c) a mechanism claim the basis never exercised. P2's basis is direct-only.
if inject_defect falseclaim \
  's|report P2-operator PASS "${p2_basis#,}" "operator uid |report P2-operator PASS "${p2_basis#,}" "reached everything through the gate; operator uid |' \
  'reached everything through the gate'
then
  # `DEFECT_BLOCKED_CODE=200` lets the operator reach the blocked destination
  # directly, which is what makes P2-operator take its PASS branch at all.
  DEFECT_BLOCKED_CODE=200 \
    assert_defect_refused falseclaim 'a through-gate claim on a DIRECT basis is refused'
fi
# (d) a basis of observations that were all UNOBSERVABLE. This is the belt the
#     other three do not reach: the basis ids exist, they belong to the right
#     probe, and not one of them recorded anything. With no gate port to aim
#     at, every P1 observation is unobservable. The replacement text names NO
#     mechanism, so the claim guard cannot be what catches this and the case
#     isolates the observed-count check.
if inject_defect allunobservable \
  's|report P1 UNOBSERVED .*|report P1 PASS "${p1_basis#,}" "everything was fine"|' \
  'report P1 PASS "${p1_basis#,}" "everything was fine"'
then
  DEFECT_GATE_PORT=absent \
    assert_defect_refused allunobservable 'a PASS whose basis observed NOTHING is refused'
fi

fi   # end of the wrapper-level cases

printf '== no host override anywhere in the shipped surface ==\n'
SHIPPED="$SANDBOX/wrapper-shipped"
"$HERE/build-wrapper.sh" "$SHIPPED" >/dev/null
BAD=0
# Comment lines are stripped first: these files EXPLAIN at length why no host
# override exists, and a scanner that cannot tell an explanation from an
# implementation would force those explanations to be deleted.
strip_comments() { grep -v '^[[:space:]]*#' "$1" || true; }
for pattern in 'env_keep' 'DRILL_LOOP_ALLOWED_HOSTS' 'allow-host'; do
  if strip_comments "$SHIPPED" | grep -q -- "$pattern"; then
    printf 'FAIL  assembled wrapper contains %s outside a comment\n' "$pattern"
    BAD=1
  fi
  if strip_comments "$HERE/sudoers.d/sanctuary-drill" | grep -q -- "$pattern"; then
    printf 'FAIL  sudoers grant contains %s outside a comment\n' "$pattern"
    BAD=1
  fi
done
if [ "$BAD" -eq 0 ]; then
  printf 'ok    no env override, no allow-host flag, no env_keep\n'
  PASS=$((PASS + 1))
else
  FAIL=$((FAIL + 1))
fi

printf '\n%s passed, %s failed, %s section(s) skipped\n' "$PASS" "$FAIL" "$SKIPPED"
if [ "$SKIPPED" -ne 0 ]; then
  printf 'NOTE: a skipped section is NOT a passed section. See the SKIP lines above.\n'
fi
if [ "$FAIL" -ne 0 ]; then exit 1; fi
