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
# against a FAKE `.sanctuary` inside the sandbox home, which exercises exactly
# the same code path with none of the risk.

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
HOME_DIR="$SANDBOX/home"
mkdir -p "$HOME_DIR"
# A stand-in for the operator's real default fortress. The denylist and the
# symlink cases both aim at THIS, never at the real one.
mkdir -p "$HOME_DIR/.sanctuary"
mkdir -p "$HOME_DIR/.sanctuary-loop-good"
mkdir -p "$SANDBOX/outside/.sanctuary-loop-outside"
ln -s "$HOME_DIR/.sanctuary" "$HOME_DIR/.sanctuary-loop-evil"

ME="$(id -un)"

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
expect_reject 'outside home, valid basename' 'is not the resolved home' \
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

printf '== host rail ==\n'
expect_reject 'unknown host' 'not on the compiled-in drill-host allowlist' \
  -- "$PROBE" host 'some-random-box'
expect_reject 'daily driver by short name' 'un-overridable denylist' \
  -- "$PROBE" host 'Eriks-MacBook-Air'
expect_reject 'daily driver with .local' 'un-overridable denylist' \
  -- "$PROBE" host 'Eriks-MacBook-Air.local'
expect_reject 'daily driver as an alias' 'un-overridable denylist' \
  -- "$PROBE" host 'agents-mac-mini' 'Eriks-MacBook-Air'
expect_accept 'a legitimate drill host' 'PROBE=ACCEPT' -- "$PROBE" host 'agents-mac-mini'

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
TEST_WRAPPER="$SANDBOX/test-wrapper"
{
  printf '#!/usr/bin/env bash\nset -euo pipefail\n'
  cat "$HERE/lib/rails.sh"
  cat "$HERE/wrapper-main.sh"
  printf "RAILS_HOST_ALLOW='%s'\n" "$(hostname -s)"
  printf "RAILS_HOST_DENY=''\n"
  printf 'wrapper_home_of() { printf "%%s\\n" "%s"; }\n' "$HOME_DIR"
  printf 'wrapper_main "$@"\n'
} > "$TEST_WRAPPER"
chmod +x "$TEST_WRAPPER"

expect_reject 'oracle: rejected path does not print ACCEPT' 'storage rail rejected' \
  -- "$TEST_WRAPPER" check --storage "$HOME_DIR/.sanctuary" --operator-account "$ME"
expect_reject 'oracle: symlinked path does not print ACCEPT' 'storage rail rejected' \
  -- "$TEST_WRAPPER" check --storage "$HOME_DIR/.sanctuary-loop-evil" --operator-account "$ME"
# Empty is refused twice over: the wrapper's own required-argument guard fires
# first, and the rail refuses it independently (proven at rail level above).
# Empty is the value that resolves to the REAL default fortress, so two layers
# is the right number.
expect_reject 'oracle: empty storage argument' 'storage is required' \
  -- "$TEST_WRAPPER" check --storage '' --operator-account "$ME"
expect_reject 'oracle: missing --storage' 'storage is required' \
  -- "$TEST_WRAPPER" check --operator-account "$ME"
expect_reject 'oracle: operator root by name' 'operator account rejected' \
  -- "$TEST_WRAPPER" check --storage "$HOME_DIR/.sanctuary-loop-good" --operator-account root
expect_reject 'oracle: unknown flag' 'unknown or unsupported argument' \
  -- "$TEST_WRAPPER" check --storage "$HOME_DIR/.sanctuary-loop-good" --operator-account "$ME" --danger
expect_reject 'oracle: unknown verb' 'unknown verb' \
  -- "$TEST_WRAPPER" definitely-not-a-verb --storage "$HOME_DIR/.sanctuary-loop-good" --operator-account "$ME"
expect_accept 'oracle: a good path is accepted' 'WRAPPER=ACCEPT' \
  -- "$TEST_WRAPPER" check --storage "$HOME_DIR/.sanctuary-loop-good" --operator-account "$ME"

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
