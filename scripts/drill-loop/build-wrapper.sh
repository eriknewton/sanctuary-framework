#!/usr/bin/env bash
#
# build-wrapper.sh - assemble the privileged wrapper from its ONE rails source.
#
# Concatenates a fixed header + lib/rails.sh + wrapper-main.sh into a single
# self-contained artifact. This is the chokepoint that lets the installed
# root-run wrapper be self-contained (it never sources anything from the
# operator-writable repo) while the rails still have exactly one source of
# truth in version control.
#
# The output is byte-deterministic: no timestamps, no hostnames, no build ids.
# If it were not, `wrapper.sha256` could never be a drift detector.
#
# Usage:
#   build-wrapper.sh [output-path]      default: build/sanctuary-drill-wrapper
#   build-wrapper.sh --stdout           write the artifact to stdout
#   build-wrapper.sh --write-hash       rebuild and refresh wrapper.sha256
#   build-wrapper.sh --verify-hash      rebuild and FAIL if wrapper.sha256 drifted

set -euo pipefail

HERE="$(CDPATH='' cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
RAILS="$HERE/lib/rails.sh"
MAIN="$HERE/wrapper-main.sh"
HASH_FILE="$HERE/wrapper.sha256"

die() {
  printf 'build-wrapper: %s\n' "$*" >&2
  exit 1
}

[ -f "$RAILS" ] || die "missing $RAILS"
[ -f "$MAIN" ] || die "missing $MAIN"

emit() {
  cat <<'HEADER'
#!/bin/bash
#
# sanctuary-drill-wrapper - GENERATED ARTIFACT. DO NOT EDIT.
#
# Assembled by scripts/drill-loop/build-wrapper.sh from:
#   scripts/drill-loop/lib/rails.sh   (the single rail source)
#   scripts/drill-loop/wrapper-main.sh
#
# Edit those files and re-run build-wrapper.sh --write-hash, then reinstall.
# The driver refuses to run when the repo, the committed hash, and the
# installed file disagree, so an unreinstalled edit is caught, not silently
# ignored.
#
# This file runs as ROOT under a NOPASSWD sudoers grant. It is deliberately
# self-contained: it sources nothing at runtime, so no write to the repo (or to
# any other operator-writable path) can become root code execution.
#
# WHY THE SHEBANG IS ABSOLUTE AND WHY PATH IS THE FIRST EXECUTABLE LINE
#
# The 2026-07-25 re-review defeated the previous header, twice, by execution:
#
#   * a planted `bash` earlier in PATH substituted the INTERPRETER of a
#     root-run artifact outright, because `#!/usr/bin/env bash` asks PATH which
#     bash to be. Even with a well-formed PATH, on a Mac with Homebrew that
#     selects /opt/homebrew/bin/bash, an OPERATOR-WRITABLE interpreter, to run
#     as root. That case needs no manipulation at all.
#   * a planted `hostname` made the wrapper print WRAPPER=ACCEPT on the
#     operator's MacBook Air, the one machine the design says is structurally
#     unable to run it. The "un-overridable" host denylist was exactly as
#     strong as whatever `hostname` resolved to.
#
# So: an absolute interpreter, and PATH pinned to root-owned system
# directories BEFORE any external command can run. /usr/local/bin is
# deliberately absent; it is operator-writable on a Mac. The sudoers grant adds
# `secure_path` as well, and lib/rails.sh resolves every security-relevant
# command by absolute path regardless of PATH. Three layers, because two of
# them were shown to be defeatable on their own.

PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
set -euo pipefail
IFS=$' \t\n'
umask 022
HEADER
  printf '\n# ==== BEGIN lib/rails.sh ====\n'
  cat "$RAILS"
  printf '\n# ==== END lib/rails.sh ====\n'
  printf '\n# ==== BEGIN wrapper-main.sh ====\n'
  cat "$MAIN"
  printf '\n# ==== END wrapper-main.sh ====\n'
  # The entrypoint lives here, not in wrapper-main.sh, so that file stays pure
  # definitions and the test battery can compose the same parts with narrow
  # overrides in between. One fixed footer, emitted identically every build.
  printf '\nwrapper_main "$@"\n'
}

sha_of_file() {
  local out
  if out="$(sha256sum "$1" 2>/dev/null)"; then printf '%s\n' "${out%% *}"; return 0; fi
  if out="$(shasum -a 256 "$1" 2>/dev/null)"; then printf '%s\n' "${out%% *}"; return 0; fi
  die 'no sha256sum or shasum available'
}

case "${1:---default}" in
  --stdout)
    emit
    ;;
  --write-hash)
    tmp="$(mktemp)"
    emit > "$tmp"
    sha_of_file "$tmp" > "$HASH_FILE"
    rm -f "$tmp"
    printf 'wrote %s: %s\n' "$HASH_FILE" "$(cat "$HASH_FILE")"
    ;;
  --verify-hash)
    tmp="$(mktemp)"
    emit > "$tmp"
    got="$(sha_of_file "$tmp")"
    rm -f "$tmp"
    [ -f "$HASH_FILE" ] || die "missing $HASH_FILE (run --write-hash)"
    want="$(tr -d ' \t\n\r' < "$HASH_FILE")"
    if [ "$got" != "$want" ]; then
      die "wrapper drift: assembled $got != committed $want (run --write-hash and reinstall)"
    fi
    printf 'wrapper hash OK: %s\n' "$got"
    ;;
  --default)
    out="$HERE/build/sanctuary-drill-wrapper"
    mkdir -p "$(dirname -- "$out")"
    emit > "$out"
    chmod 0755 "$out"
    printf '%s\n' "$out"
    ;;
  *)
    out="$1"
    mkdir -p "$(dirname -- "$out")"
    emit > "$out"
    chmod 0755 "$out"
    printf '%s\n' "$out"
    ;;
esac
