#!/usr/bin/env bash
#
# host-fingerprint.sh - print THIS machine's drill-host fingerprint.
#
# Run this once on each drill host and paste the printed value into
# RAILS_HOST_ALLOW_FP in lib/rails.sh, with the machine named in a comment.
# That list is the entire host allowlist, so the diff that adds a line here is
# a diff that must be reviewed.
#
#     scripts/drill-loop/host-fingerprint.sh
#
# WHY A FINGERPRINT AND NOT A NAME
#
# A live audit of the real machines (2026-07-25) measured the intended drill
# host answering `hostname -s` with the literal string "Mac", and reporting no
# `scutil --get HostName` at all. A name allowlist able to admit that machine
# would admit a large fraction of default-configured Macs, which turns "fail
# closed on an unknown host" into "pass on many unknown hosts". Names are also
# forgeable: an adversarial review defeated the previous rail by planting a
# `hostname` binary on PATH and got WRAPPER=ACCEPT on the operator's MacBook
# Air, the one machine the design says must never run this.
#
# So the decision is made on the machine's hardware UUID, and what gets
# committed is its SHA-256. This is a public repository: a fingerprint compares
# exactly, carries no raw machine identifier, and does not reverse into one.
#
# READ-ONLY. This script installs nothing, changes nothing, and contacts
# nothing. It reads one property out of ioreg and hashes it.

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/rails.sh
. "$HERE/lib/rails.sh"

FP="$(rails_host_fingerprint_local)" \
  || { printf 'host-fingerprint: could not establish this machine hardware identity\n' >&2; exit 1; }
[ -n "$FP" ] || { printf 'host-fingerprint: empty fingerprint after rail\n' >&2; exit 1; }

printf 'machine names (advisory only, NOT what the rail decides on):\n'
printf '  hostname -s            = %s\n' "$(rails__sys hostname -s 2>/dev/null || printf '(none)')"
printf '  hostname               = %s\n' "$(rails__sys hostname 2>/dev/null || printf '(none)')"
printf '  scutil HostName        = %s\n' "$(rails__sys scutil --get HostName 2>/dev/null || printf '(unset)')"
printf '  scutil LocalHostName   = %s\n' "$(rails__sys scutil --get LocalHostName 2>/dev/null || printf '(unset)')"
printf '  scutil ComputerName    = %s\n' "$(rails__sys scutil --get ComputerName 2>/dev/null || printf '(unset)')"
printf '\ndrill-host fingerprint (THIS is what the rail decides on):\n\n  %s\n\n' "$FP"

for e in $RAILS_HOST_DENY_FP; do
  if [ "$FP" = "$e" ]; then
    printf 'This machine is on the un-overridable DENYLIST. It must never run the\n'
    printf 'drill wrapper, and adding it to the allowlist would not change that:\n'
    printf 'the denylist is checked first and no argument can widen it.\n'
    exit 0
  fi
done
for e in $RAILS_HOST_ALLOW_FP; do
  if [ "$FP" = "$e" ]; then
    printf 'This machine is ALREADY on the drill-host allowlist. Nothing to do.\n'
    exit 0
  fi
done

printf 'This machine is NOT on the allowlist, so the wrapper refuses here.\n'
printf 'To allow it, add the fingerprint above to RAILS_HOST_ALLOW_FP in\n'
printf 'scripts/drill-loop/lib/rails.sh, name the machine in a comment, rebuild\n'
printf 'with build-wrapper.sh --write-hash, and get the diff re-reviewed.\n'
