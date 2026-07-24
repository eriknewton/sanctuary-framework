#!/usr/bin/env bash
#
# probe.sh - the rails exercised through the EXACT call-site form the wrapper
# and drivers use.
#
# Why this exists rather than tests calling the rail functions directly: the
# reviewed build's BLOCKER was not in a rail's logic, it was in the CALL SITE.
# `assert_disposable_storage` did reject the path; it just did so with a `die`
# inside `$(...)`, which killed only the subshell, so the parent sailed on with
# an empty storage value and armed the real fortress as root. A test that calls
# the function and checks its return value would have passed on that build.
#
# So every case here goes through the mandated shape:
#
#   VALUE="$(rails_... "$@")" || die "rail rejected"
#   [ -n "$VALUE" ] || die "empty after rail"
#   printf 'PROBE=ACCEPT ...'
#
# A rejection must therefore produce a NONZERO exit AND no ACCEPT token. Both
# halves matter: "nonzero exit" alone would have been satisfied by a build that
# printed ACCEPT and then failed later, and "no ACCEPT" alone would have been
# satisfied by a build that fell through silently.
#
# Usage:
#   probe.sh storage <home> <candidate>
#   probe.sh host <primary> [alias...]
#   probe.sh account <label> <account>
#   probe.sh uid <label> <account> <uid>
#   probe.sh account-uid <label> <account> <expected-uid>
#   probe.sh secret <file> <owner-account>
#   probe.sh lock <lockdir> <max-wait-seconds>
#   probe.sh wrapper-hash <assembled> <installed> <sha-file>
#   probe.sh wrapper-ownership <installed>
#   probe.sh wrapper-integrity <assembled> <installed> <sha-file>

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=rails.sh
. "$HERE/rails.sh"

die() {
  printf 'PROBE=REJECT reason=%s\n' "$*" >&2
  exit 9
}

kind="${1:-}"
if [ -z "$kind" ]; then die 'no probe kind given'; fi
shift

case "$kind" in
  storage)
    # Arguments are forwarded verbatim, including a WRONG NUMBER of them, so
    # the rail's own arity check is what fires. A probe that pre-screened arity
    # would hide a rail that accepted a missing argument.
    STORAGE="$(rails_assert_disposable_storage "$@")" || die "storage rail rejected: ${2:-<missing>}"
    if [ -z "$STORAGE" ]; then die 'empty storage after rail'; fi
    printf 'PROBE=ACCEPT storage=%s\n' "$STORAGE"
    ;;
  host)
    if [ "$#" -lt 1 ]; then die 'host needs at least <primary>'; fi
    rails_assert_host_allowed "$@" || die "host rail rejected: $1"
    printf 'PROBE=ACCEPT host=%s\n' "$1"
    ;;
  account)
    if [ "$#" -ne 2 ]; then die 'account needs <label> <account>'; fi
    UID_OUT="$(rails_assert_non_root_account "$1" "$2")" || die "account rail rejected: $2"
    if [ -z "$UID_OUT" ]; then die 'empty uid after rail'; fi
    printf 'PROBE=ACCEPT account=%s uid=%s\n' "$2" "$UID_OUT"
    ;;
  uid)
    if [ "$#" -ne 3 ]; then die 'uid needs <label> <account> <uid>'; fi
    rails_assert_nonroot_uid "$1" "$2" "$3" || die "uid rail rejected: $3"
    printf 'PROBE=ACCEPT account=%s uid=%s\n' "$2" "$3"
    ;;
  account-uid)
    if [ "$#" -ne 3 ]; then die 'account-uid needs <label> <account> <expected-uid>'; fi
    UID_OUT="$(rails_assert_account_uid "$1" "$2" "$3")" || die "account-uid rail rejected: $2"
    if [ -z "$UID_OUT" ]; then die 'empty uid after rail'; fi
    printf 'PROBE=ACCEPT account=%s uid=%s\n' "$2" "$UID_OUT"
    ;;
  secret)
    if [ "$#" -ne 2 ]; then die 'secret needs <file> <owner-account>'; fi
    rails_assert_secret_file_perms "$1" "$2" || die "secret-file rail rejected: $1"
    printf 'PROBE=ACCEPT secret=%s\n' "$1"
    ;;
  lock)
    if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
      die 'lock needs <lockdir> <max-wait-seconds> [hold-seconds]'
    fi
    rails_lock_acquire "$1" "$2" || die "lock rail rejected: $1"
    printf 'PROBE=ACCEPT lock=%s pid=%s\n' "$1" "$$"
    # HOLD before releasing. Without this, a concurrency test proves nothing:
    # the first process acquires and releases so fast that the second one
    # legitimately acquires a now-free lock afterwards, and "two winners" is a
    # correct outcome for a serialized pair rather than evidence of a race.
    # Holding is what makes the contention real, and it is what keeps the
    # steal window (A reclaims a stale lock, B wins the fresh mkdir, C renames
    # B's LIVE lock away) wide open for a broken implementation to fall into.
    if [ "$#" -eq 3 ] && [ "$3" != '0' ]; then sleep "$3"; fi
    rails_lock_release "$1"
    ;;
  wrapper-hash)
    if [ "$#" -ne 3 ]; then die 'wrapper-hash needs <assembled> <installed> <sha-file>'; fi
    rails_assert_wrapper_hash "$1" "$2" "$3" || die 'wrapper-hash rail rejected'
    printf 'PROBE=ACCEPT wrapper-hash=ok\n'
    ;;
  wrapper-ownership)
    if [ "$#" -ne 1 ]; then die 'wrapper-ownership needs <installed>'; fi
    rails_assert_wrapper_ownership "$1" || die 'wrapper-ownership rail rejected'
    printf 'PROBE=ACCEPT wrapper-ownership=ok\n'
    ;;
  wrapper-integrity)
    if [ "$#" -ne 3 ]; then die 'wrapper-integrity needs <assembled> <installed> <sha-file>'; fi
    rails_assert_wrapper_integrity "$1" "$2" "$3" || die 'wrapper-integrity rail rejected'
    printf 'PROBE=ACCEPT wrapper-integrity=ok\n'
    ;;
  *)
    die "unknown probe kind: $kind"
    ;;
esac
