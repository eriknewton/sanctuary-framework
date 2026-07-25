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
expect_accept 'plain run id' 'PROBE=ACCEPT'          -- "$PROBE" run-id '20260725T0230-1'
expect_reject 'empty run id' 'empty run id'          -- "$PROBE" run-id ''
expect_reject 'run id with a slash' 'disallowed characters' -- "$PROBE" run-id 'a/b'
expect_reject 'run id traversal' 'disallowed characters'    -- "$PROBE" run-id '../evil'
expect_reject 'run id leading dot' 'must start with a letter or a digit' -- "$PROBE" run-id '.hidden'
expect_reject 'option-shaped run id' 'must start with a letter or a digit' -- "$PROBE" run-id '-rf'
expect_reject 'over-long run id' 'longer than' \
  -- "$PROBE" run-id 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
expect_accept 'derivation composes the path' ".sanctuary-loop-x1" \
  -- "$PROBE" derive "$BASE" "$ME" 'x1'
expect_reject 'derivation refuses a relative base' 'not an absolute path' \
  -- "$PROBE" derive 'relative/base' "$ME" 'x1'
expect_reject 'derivation refuses root as operator' 'disallowed characters' \
  -- "$PROBE" derive "$BASE" 'ro ot' 'x1'

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

printf '== host rail ==\n'
expect_reject 'unknown host' 'not on the compiled-in drill-host allowlist' \
  -- "$PROBE" host 'some-random-box'
expect_reject 'daily driver by short name' 'un-overridable denylist' \
  -- "$PROBE" host 'Eriks-MacBook-Air'
expect_reject 'daily driver with .local' 'un-overridable denylist' \
  -- "$PROBE" host 'Eriks-MacBook-Air.local'
expect_reject 'daily driver as an alias' 'un-overridable denylist' \
  -- "$PROBE" host 'agents-mac-mini' 'Eriks-MacBook-Air'
# The `scutil --get ComputerName` form. It carries spaces and a curly
# apostrophe, so a space-separated denylist cannot hold it literally; the
# denylist compares an aggressively normalized form for exactly this reason.
# Before the fix this name was rejected by the ALLOWLIST (fail closed) while
# the rail's own comment claimed the denylist covered it.
expect_reject 'daily driver as its ComputerName' 'un-overridable denylist' \
  -- "$PROBE" host "Erik's MacBook Air"
expect_reject 'ComputerName as an extra alias' 'un-overridable denylist' \
  -- "$PROBE" host 'agents-mac-mini' "Erik's MacBook Air"
expect_accept 'a legitimate drill host' 'PROBE=ACCEPT' -- "$PROBE" host 'agents-mac-mini'

# The wrapper's ACTUAL call shape: three observed identities, any of which may
# be empty. The reviewed wrapper chose between three if/elif branches that
# passed different subsets, and one of them silently DROPPED the ComputerName
# alias. A rail can only refuse what it is shown.
expect_accept 'observed: only a short name' 'PROBE=ACCEPT' \
  -- "$PROBE" host-observed 'agents-mac-mini' '' ''
expect_accept 'observed: short name plus a full name' 'PROBE=ACCEPT' \
  -- "$PROBE" host-observed 'agents-mac-mini' 'agents-mac-mini.local' ''
expect_reject 'observed: a denied name in the SECOND position' 'un-overridable denylist' \
  -- "$PROBE" host-observed 'agents-mac-mini' 'Eriks-MacBook-Air' ''
expect_reject 'observed: a denied name in the THIRD position, no second' 'un-overridable denylist' \
  -- "$PROBE" host-observed 'agents-mac-mini' '' "Erik's MacBook Air"
expect_reject 'observed: nothing at all was observed' 'no host identity could be observed' \
  -- "$PROBE" host-observed '' '' ''

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
"$HERE/build-wrapper.sh" --stdout \
  | awk -v host="$(hostname -s)" -v base="$BASE" '
      $0 == "wrapper_main \"$@\"" {
        print "RAILS_HOST_ALLOW=\047" tolower(host) "\047"
        print "RAILS_HOST_DENY=\047\047"
        print "RAILS_DISPOSABLE_BASE=\047" base "\047"
      }
      { print }
    ' > "$TEST_WRAPPER"
chmod +x "$TEST_WRAPPER"

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
expect_reject 'kickstart-daemons reports a failed restart' 'kickstart failed for' \
  -- "$TEST_WRAPPER" kickstart-daemons --run-id 'good1' --operator-account "$ME"
# The verb behind the pf fail-closed fix, driven directly. `pfctl` needs root
# (and does not exist on Linux at all), so a non-root run here MUST refuse
# rather than print an empty anchor and call it success. That is the whole
# point: "could not read" and "read, and it was empty" must be two answers.
if [ "$(id -u)" -ne 0 ]; then
  expect_reject 'pf-anchor-rules refuses when pfctl cannot run' 'could not read the pf anchor' \
    -- "$TEST_WRAPPER" pf-anchor-rules --run-id 'good1' --operator-account "$ME"
fi
# Every verb refuses a bad run id before doing anything at all.
for v in mint clean-markers gate-state kickstart-daemons repair unprotect pf-anchor-rules; do
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
# The driver is UNPRIVILEGED, so it can be driven for real here with a stub
# `sudo` earlier in PATH. That is what makes this a test rather than an
# argument: delete the fail-closed branch and this case goes red.
STUBBIN="$SANDBOX/stubbin"
mkdir -p "$STUBBIN"
cat > "$STUBBIN/sudo" <<'STUB'
#!/bin/bash
# Stub `sudo` for the driver battery. Understands the two shapes the drivers
# use: `sudo -n <wrapper> <verb> ...` and `sudo -n -u <acct> -- <cmd> ...`.
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
    unprotect|clean-markers) exit "${STUB_WRAPPER_RC:-0}" ;;
    curl)
      if [ "${STUB_CURL:-ok}" = 'refused' ]; then
        echo 'sudo: a password is required' >&2
        exit 1
      fi
      echo "${STUB_CURL_CODE:-200}"; exit 0 ;;
  esac
done
exit 0
STUB
chmod +x "$STUBBIN/sudo"

TD_EV="$SANDBOX/teardown-evidence"
run_teardown() {
  PATH="$STUBBIN:$PATH" "$HERE/drivers/teardown-verify.sh" \
    --run-id 'good1' --operator-account "$ME" \
    --agent-account "$ME" --agent-uid "$(id -u)" \
    --evidence-dir "$TD_EV" --base "$BASE" 2>&1
}

set +e   # declared exception: these runs are EXPECTED to exit nonzero
out="$(STUB_PF=refused run_teardown)"; rc=$?
set -e
case "$out" in
  *'VERIFY=DIRTY check=pf-anchor'*)
    if [ "$rc" -ne 0 ]; then
      printf 'ok    a pf anchor that could not be READ is DIRTY, not clean (exit %s)\n' "$rc"
      PASS=$((PASS + 1))
    else
      printf 'FAIL  teardown-verify said DIRTY but exited 0\n'
      FAIL=$((FAIL + 1))
    fi
    ;;
  *)
    printf 'FAIL  *** a refused pf read was reported CLEAN; the fail-open is back ***\n'
    note "output: $out"
    FAIL=$((FAIL + 1))
    ;;
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
# ROOT-owned, so after the first arm the unprivileged driver genuinely cannot
# look inside. Reporting CLEAN there would be the 2026-06-24 failure again.
# Two layers can produce that refusal and the case asserts the PROPERTY rather
# than either layer, because which one fires depends on how the fortress became
# unreadable. As an unprivileged process the reachable state is "cannot
# traverse", and the storage rail's own `cd -P` post-condition catches it first
# and exits hard; the explicit `storage_observable` check covers the
# traversable-but-not-readable case (a 0711 fortress owned by someone else),
# which cannot be constructed here without root.
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
  *'VERIFY=DIRTY check=agent-unconfined reason=could not RUN the as-agent probe'*)
    printf 'ok    an as-agent probe that could not RUN is DIRTY, and says which\n'
    PASS=$((PASS + 1)) ;;
  *)
    printf 'FAIL  a probe that could not run was not reported as unobservable\n'
    note "output: $out"; FAIL=$((FAIL + 1)) ;;
esac

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

printf '\n%s passed, %s failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then exit 1; fi
