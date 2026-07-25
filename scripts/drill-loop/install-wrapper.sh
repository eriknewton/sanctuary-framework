#!/usr/bin/env bash
#
# install-wrapper.sh - install the assembled wrapper to /usr/local/sbin.
#
# THIS SCRIPT WAS NOT RUN BY THE BUILD THAT ADDED IT. It is documented,
# reviewable, and deliberately unexecuted: installing it plus the sudoers line
# is the one-time physical-necessity step that belongs to the operator, and it
# must not happen until an independent review confirms the rails fail closed.
#
# Run as root, on a drill host only:
#   sudo scripts/drill-loop/install-wrapper.sh
#
# What it does, in order:
#   1. refuses to run on a host outside the compiled-in allowlist (the same
#      rail the wrapper itself uses, so you cannot install onto the MacBook);
#   2. re-assembles the wrapper from the repo and verifies it against the
#      committed wrapper.sha256, so an unbuilt edit cannot be installed;
#   3. writes it root:wheel 0755 into /usr/local/sbin, atomically;
#   4. re-verifies the installed file's hash and prints the sudoers line.

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=lib/rails.sh
. "$HERE/lib/rails.sh"

DEST_DIR='/usr/local/sbin'
DEST="$DEST_DIR/sanctuary-drill-wrapper"

die() {
  printf 'install-wrapper: %s\n' "$*" >&2
  exit 1
}

if [ "$(id -u)" -ne 0 ]; then die 'must run as root (sudo)'; fi

# Same host rail the wrapper enforces, applied to the install itself. The
# subshell makes the rail's `exit` a status this script can act on, so the
# refusal message is this file's and not a bare RAILS_REJECT line; and
# `hostname` / `scutil` go through the absolute resolver, because the review
# defeated the host rail with a planted `hostname` on PATH.
( rails_assert_host_allowed_observed \
    "$(rails__sys hostname -s 2>/dev/null || printf '')" \
    "$(rails__sys hostname -f 2>/dev/null || printf '')" \
    "$(rails__sys scutil --get ComputerName 2>/dev/null || printf '')" ) \
  || die 'host rail rejected this machine; refusing to install'

"$HERE/build-wrapper.sh" --verify-hash >/dev/null \
  || die 'assembled wrapper does not match wrapper.sha256; run build-wrapper.sh --write-hash and re-review'

TMP="$(mktemp "${TMPDIR:-/tmp}/sanctuary-drill-wrapper.XXXXXX")"
trap 'rm -f "$TMP"' EXIT
"$HERE/build-wrapper.sh" --stdout > "$TMP"

mkdir -p "$DEST_DIR"
chown root:wheel "$DEST_DIR" 2>/dev/null || chown root:root "$DEST_DIR"
chmod 0755 "$DEST_DIR"

install -o root -g wheel -m 0755 "$TMP" "$DEST" 2>/dev/null \
  || install -o root -g root -m 0755 "$TMP" "$DEST"

# The mandatory call-site form, here too. This was the one asserting-rail call
# in the tree without an explicit `|| die`; it was safe only because this file
# has `set -e`, and relying on `set -e` alone is precisely the thing this
# codebase decided not to do after round 1.
WANT="$(tr -d ' \t\n\r' < "$HERE/wrapper.sha256")" || die 'cannot read the committed hash'
GOT="$(rails_sha256_file "$DEST")" || die "cannot hash the installed wrapper at $DEST"
if [ -z "$GOT" ]; then die 'empty hash after the sha rail'; fi
if [ "$GOT" != "$WANT" ]; then die "installed hash $GOT != committed $WANT"; fi

printf 'installed %s (root-owned 0755, sha256 %s)\n' "$DEST" "$GOT"
printf '\nNow add the NOPASSWD grant, reviewed in scripts/drill-loop/sudoers.d/sanctuary-drill:\n\n'
cat "$HERE/sudoers.d/sanctuary-drill"
