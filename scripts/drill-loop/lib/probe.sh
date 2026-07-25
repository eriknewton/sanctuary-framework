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
#   probe.sh storage <anchor> <candidate>
#   probe.sh run-id <id>
#   probe.sh derive <base> <operator> <run-id>
#   probe.sh safe-subpath <root> <relative-path>
#   probe.sh trusted-chain <label> <path>
#   probe.sh stat-mode <path>
#   probe.sh trusted-component <path> <owner-uid> <mode> <self-uid>
#   probe.sh caller-binding <self-uid> <sudo-user> <operator>
#   probe.sh etime <etime-string>
#   probe.sh probe-result <exit-status> <probe-summary-line>
#   probe.sh fingerprint-against <fingerprint> <deny-list> <allow-list>
#   probe.sh host <fingerprint> [observed-name...]
#   probe.sh host-observed <fingerprint> [observed-name...]
#   probe.sh host-fingerprint-of <hardware-uuid>
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
  run-id)
    # Arity forwarded verbatim so the rail's own check is what fires.
    RUN_ID="$(rails_assert_run_id "$@")" || die "run-id rail rejected: ${1:-<missing>}"
    if [ -z "$RUN_ID" ]; then die 'empty run id after rail'; fi
    printf 'PROBE=ACCEPT run-id=%s\n' "$RUN_ID"
    ;;
  derive)
    DERIVED="$(rails_derive_disposable_storage "$@")" || die "derive rail rejected"
    if [ -z "$DERIVED" ]; then die 'empty derived path after rail'; fi
    printf 'PROBE=ACCEPT derived=%s\n' "$DERIVED"
    ;;
  safe-subpath)
    SAFE="$(rails_assert_safe_subpath "$@")" || die "safe-subpath rail rejected: ${2:-<missing>}"
    if [ -z "$SAFE" ]; then die 'empty path after the safe-subpath rail'; fi
    printf 'PROBE=ACCEPT safe-subpath=%s\n' "$SAFE"
    ;;
  trusted-chain)
    CHAIN="$(rails_assert_trusted_dir_chain "$@")" || die "trusted-chain rail rejected: ${2:-<missing>}"
    if [ -z "$CHAIN" ]; then die 'empty path after the trusted-chain rail'; fi
    printf 'PROBE=ACCEPT trusted-chain=%s\n' "$CHAIN"
    ;;
  stat-mode)
    # The MODE READER, driven on a real path. Split out because the sticky-bit
    # carve-out in `rails_assert_trusted_component` is decided on this
    # function's output, and on macOS the BSD branch used to read `%Lp`, which
    # DROPS the high bits: `/private/tmp` measured `777` for a directory whose
    # real mode is `1777`, so the carve-out could never fire on the platform the
    # drill runs on. A predicate that behaves differently on macOS and Linux
    # while documented as working on both is a defect even when it fails safe.
    if [ "$#" -ne 1 ]; then die 'stat-mode needs <path>'; fi
    MODE="$(rails__stat_mode "$1")" || die "cannot stat: $1"
    if [ -z "$MODE" ]; then die 'empty mode after the stat reader'; fi
    printf 'PROBE=ACCEPT mode=%s\n' "$MODE"
    ;;
  trusted-component)
    # The PURE predicate, driven directly. It prints nothing, so the mandatory
    # form here is the subshell one the wrapper uses for its non-printing rails.
    ( rails_assert_trusted_component "$@" ) || die "trusted-component rail rejected: ${1:-<missing>}"
    printf 'PROBE=ACCEPT trusted-component=%s\n' "${1:-}"
    ;;
  caller-binding)
    ( rails_assert_caller_binding "$@" ) || die "caller-binding rail rejected"
    printf 'PROBE=ACCEPT caller-binding=%s\n' "${3:-}"
    ;;
  etime)
    SECS="$(rails_etime_to_seconds "$@")" || die "etime rail rejected: ${1:-<missing>}"
    if [ -z "$SECS" ]; then die 'empty seconds after the etime rail'; fi
    printf 'PROBE=ACCEPT seconds=%s\n' "$SECS"
    ;;
  probe-result)
    # The fold `run-loop.sh` writes into FINDINGS.jsonl. Driven here so every
    # (status, summary) pair can be asserted, including the ones a live night
    # would take weeks to produce.
    RESULT="$(rails_probe_result "$@")" || die "probe-result rail rejected"
    if [ -z "$RESULT" ]; then die 'empty result after the probe-result rail'; fi
    printf 'PROBE=ACCEPT probe-result=%s\n' "$RESULT"
    ;;
  host)
    # host <fingerprint> [observed-name...]. The FINGERPRINT is the decision;
    # names are a deny-only belt.
    if [ "$#" -lt 1 ]; then die 'host needs at least <fingerprint>'; fi
    ( rails_assert_host_allowed "$@" ) || die "host rail rejected"
    printf 'PROBE=ACCEPT host-fingerprint=%s\n' "$1"
    ;;
  host-observed)
    # The wrapper's ACTUAL call shape: a fingerprint plus several observed
    # names, any of which may be empty. Drives the collection, not just the
    # comparison.
    if [ "$#" -lt 1 ]; then die 'host-observed needs at least <fingerprint>'; fi
    ( rails_assert_host_allowed_observed "$@" ) || die "host rail rejected"
    printf 'PROBE=ACCEPT host-observed=%s\n' "${1:-<empty>}"
    ;;
  fingerprint-against)
    # The PURE decision: <fingerprint> <deny-list> <allow-list>. This is the
    # only way to exercise the ACCEPT path, because the shipped allowlist is
    # deliberately empty until a drill host is measured.
    if [ "$#" -ne 3 ]; then die 'fingerprint-against needs <fp> <deny> <allow>'; fi
    ( rails_assert_fingerprint_against "$1" "$2" "$3" ) || die "fingerprint rail rejected"
    printf 'PROBE=ACCEPT fingerprint-against=%s\n' "$1"
    ;;
  host-fingerprint-of)
    if [ "$#" -ne 1 ]; then die 'host-fingerprint-of needs <uuid>'; fi
    FP="$(rails_host_fingerprint_of "$1")" || die "host fingerprint rail rejected: $1"
    if [ -z "$FP" ]; then die 'empty fingerprint after rail'; fi
    printf 'PROBE=ACCEPT fingerprint=%s\n' "$FP"
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
