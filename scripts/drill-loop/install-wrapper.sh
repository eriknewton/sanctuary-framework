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
#   3. asserts that EVERY component of the grant target's directory is a
#      root-owned, non-writable, non-symlink chain;
#   4. hashes the assembled TEMP file and refuses BEFORE writing anything;
#   5. writes it root:wheel 0755 into /usr/local/sbin;
#   6. re-verifies the installed file's hash, REMOVING it on any mismatch, and
#      prints the sudoers line.
#
# THE ORDER IN 4-6 IS THE ROUND-3 M3 FIX. This used to install first and verify
# second, so on any mismatch it exited leaving a root-owned 0755 file that did
# NOT match the committed hash sitting at exactly the path the NOPASSWD grant
# names. `run-loop.sh` would refuse to use it; a hand-run `sudo
# /usr/local/sbin/sanctuary-drill-wrapper` would not, and on a re-install over
# an existing grant the window was real. And step 3 exists because
# `rails_assert_wrapper_ownership` checks the FILE and never the chain above it:
# on an Intel Mac, Homebrew owns `/usr/local`, so an operator-writable
# `/usr/local/sbin` would let the operator replace the grant target outright.

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
    "$(rails_host_fingerprint_local)" \
    "$(rails__sys hostname -s 2>/dev/null || printf '')" \
    "$(rails__sys hostname -f 2>/dev/null || printf '')" \
    "$(rails__sys scutil --get ComputerName 2>/dev/null || printf '')" \
    "$(rails__sys scutil --get LocalHostName 2>/dev/null || printf '')" ) \
  || die 'host rail rejected this machine; refusing to install (if this IS a drill host, run scripts/drill-loop/host-fingerprint.sh and add its fingerprint to RAILS_HOST_ALLOW_FP)'

"$HERE/build-wrapper.sh" --verify-hash >/dev/null \
  || die 'assembled wrapper does not match wrapper.sha256; run build-wrapper.sh --write-hash and re-review'

# Assemble into a ROOT-OWNED temp directory, not into $TMPDIR. This script runs
# as root; a world-writable temp parent is the wrong place to stage the exact
# bytes that are about to become a NOPASSWD grant target.
STAGE="$(mktemp -d /var/tmp/sanctuary-drill-install.XXXXXX)"
chown root:wheel "$STAGE" 2>/dev/null || chown root:root "$STAGE"
chmod 0700 "$STAGE"
trap 'rm -rf "$STAGE"' EXIT
TMP="$STAGE/sanctuary-drill-wrapper"
"$HERE/build-wrapper.sh" --stdout > "$TMP"
chmod 0755 "$TMP"

mkdir -p "$DEST_DIR"
chown root:wheel "$DEST_DIR" 2>/dev/null || chown root:root "$DEST_DIR"
chmod 0755 "$DEST_DIR"

# EVERY component of the grant target's directory, not just the file that will
# land in it (round-3 M3).
( rails_assert_trusted_dir_chain 'grant target dir' "$DEST_DIR" >/dev/null ) \
  || die "$DEST_DIR is not a trusted root-owned chain; refusing to install a NOPASSWD grant target into it"

# VERIFY FIRST, INSTALL SECOND. The mandatory call-site form, here too: this was
# the one asserting-rail call in the tree without an explicit `|| die`, and it
# was safe only because this file has `set -e`.
WANT="$(tr -d ' \t\n\r' < "$HERE/wrapper.sha256")" || die 'cannot read the committed hash'
STAGED="$(rails_sha256_file "$TMP")" || die "cannot hash the staged wrapper at $TMP"
if [ -z "$STAGED" ]; then die 'empty hash after the sha rail'; fi
if [ "$STAGED" != "$WANT" ]; then
  die "staged hash $STAGED != committed $WANT; NOTHING was written to $DEST"
fi

install -o root -g wheel -m 0755 "$TMP" "$DEST" 2>/dev/null \
  || install -o root -g root -m 0755 "$TMP" "$DEST"

# And re-read what actually landed. On any mismatch REMOVE it: leaving a
# root-owned 0755 file that does not match the reviewed hash at the path the
# grant names is worse than having no wrapper at all.
GOT="$(rails_sha256_file "$DEST")" || { rm -f "$DEST"; die "cannot hash the installed wrapper at $DEST (removed it)"; }
if [ "$GOT" != "$WANT" ]; then
  rm -f "$DEST"
  die "installed hash $GOT != committed $WANT; REMOVED $DEST rather than leave an unreviewed grant target in place"
fi

printf 'installed %s (root-owned 0755, sha256 %s)\n' "$DEST" "$GOT"
printf '\nNow add the NOPASSWD grant, reviewed in scripts/drill-loop/sudoers.d/sanctuary-drill:\n\n'
cat "$HERE/sudoers.d/sanctuary-drill"
