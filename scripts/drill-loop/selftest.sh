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
    | awk -v fp="$LOCAL_FP" -v base="$BASE" -v agents="$2" -v gatebase="${3:-/var/sanctuary-agents}" -v bins="${4:-}" '
        $0 == "wrapper_main \"$@\"" {
          print "RAILS_HOST_ALLOW_FP=\047" fp "\047"
          print "RAILS_HOST_DENY_FP=\047\047"
          print "RAILS_HOST_DENY=\047\047"
          print "RAILS_DISPOSABLE_BASE=\047" base "\047"
          print "RAILS_AGENT_ACCOUNT_ALLOW=\047" agents "\047"
          print "RAILS_PRODUCT_GATE_HOME_BASE=\047" gatebase "\047"
          if (bins != "") print "RAILS_SYSTEM_BIN_DIRS=\047" bins "\047"
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
for v in kickstart-daemons gate-state gate-log; do
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
# ...and the same account IS accepted once it is on the allowlist, so the rail
# has been seen to say yes as well as no.
expect_reject 'an allowlisted agent account passes the agent rail and dies later' 'kickstart failed for' \
  -- "$TEST_WRAPPER_AGENT" kickstart-daemons --run-id 'good1' --operator-account "$ME" \
     --agent-account "$ME" --agent-uid "$(id -u)"
# Every verb refuses a bad run id before doing anything at all.
for v in mint clean-markers gate-state kickstart-daemons repair unprotect retire \
         pf-anchor-rules registry-state fortress-state gate-log; do
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
    kickstart-daemons)       exit "${STUB_KICKSTART_RC:-0}" ;;
    mint)                    exit "${STUB_MINT_RC:-0}" ;;
    retire)                  exit "${STUB_RETIRE_RC:-0}" ;;
    unprotect|clean-markers) exit "${STUB_WRAPPER_RC:-0}" ;;
    *curl)
      if [ "${STUB_CURL:-ok}" = 'refused' ]; then
        echo 'sudo: a password is required' >&2
        exit 1
      fi
      # The BLOCKED endpoint answers with a denial, so a battery run's only
      # remaining problem can be the one the case is about.
      for u in "${args[@]}"; do
        case "$u" in
          https://example.com) echo "${STUB_BLOCKED_CODE:-${STUB_CURL_CODE:-200}}"; exit 0 ;;
        esac
      done
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

# --- THE PROBE BATTERY: A SKIP IS NOT A PASS (Codex round-3 finding 2) ----
#
# The battery reported `N3 SKIP`, left FAILED at zero, exited 0, and the loop
# wrote `"result":"PASS"` for the whole probe step. Two independent things now
# have to be true before that can happen: exit 0 AND `verified=yes`.
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
  *'PROBE=SUMMARY'*'skipped=P1-reason'*)
    printf 'ok    the summary NAMES the probes that did not run\n'; PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  the summary did not name the skipped probes\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac
# And the round-4 N3 rule: a wrong-uid request that SUCCEEDED is a FAIL before
# the log reason is even considered. Stale or even current-looking
# peer_uid_mismatch text cannot turn an allowed request into a passing denial.
set +e   # declared exception
out="$(STUB_GATE_LOG=ok STUB_GATE_LOG_BODY="peer=$(id -u) allowlist peer_uid_mismatch" STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 run_probes)"; rc=$?
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
set +e   # declared exception
out="$(STUB_GATE_LOG=ok STUB_GATE_LOG_BODY='old allowlist' STUB_GATE_LOG_SINCE_BODY="peer=$(id -u)" STUB_CURL_CODE=200 STUB_BLOCKED_CODE=403 run_probes)"; rc=$?
set -e
case "$out" in
  *'PROBE=N1 RESULT=FAIL'*'current log window'*)
    printf 'ok    stale allowlist text outside the current window cannot pass N1\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  *** stale allowlist text satisfied N1 without current evidence ***\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

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
