#!/usr/bin/env bash
#
# Mint the proof that the Secret Service on this session bus is a throwaway one
# that CI created for this run, and print the path of the token file holding it.
#
# Consumed by server/test/support/real-backend-guard.ts, which is the gate on
# the one test file that removes the in-memory credential store. That file
# shells out to a genuine `secret-tool`, so the wrong answer here means writing
# into somebody's real keyring.
#
# The declaration this replaces was `SANCTUARY_TEST_DISPOSABLE_KEYRING=1`. A
# Linux desktop has `secret-tool` and a session bus, so a single stale export in
# a shell profile was the entire distance between "skip" and "write to the
# operator's own Secret Service". What is produced instead is run-specific and
# cannot survive as an exported variable:
#
#   nonce        a fresh 32 random bytes, stored INTO the keyring and recorded
#                in the token, so the guard can prove the keyring answering on
#                this bus is the one this script wrote to
#   dbusAddress  the exact bus this ran against, so a token that outlives its
#                bus never matches a later one
#   createdAtMs  a wall-clock stamp, so a token left on disk goes stale
#
# The bus itself is checked first: this refuses to run against a login-session
# bus (/run/user/<uid>/bus), which is what a developer's desktop has. That is
# the condition their machine is structurally unable to satisfy.
#
# Failure mode to recognize: every failure here is fatal and loud. It has to be.
# If this exited 0 without producing a token, the integration suite would skip,
# the job would stay green, and the real-backend coverage would evaporate in
# silence. The exact-count guard in the workflow is the second line of defense;
# this is the first.
#
# Usage:  TOKEN_PATH="$(scripts/ci/provision-disposable-keyring.sh)"

set -euo pipefail

# MUST MATCH PROBE_SERVICE / PROBE_ACCOUNT in
# server/test/support/real-backend-guard.ts.
PROBE_SERVICE="sanctuary-disposable-keyring-probe"
PROBE_ACCOUNT="nonce"

if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
  echo "provision-disposable-keyring: DBUS_SESSION_BUS_ADDRESS is not set; start a throwaway bus first (dbus-run-session / dbus-launch)" >&2
  exit 1
fi

# Extract the socket identifier from the address. `unix:abstract=/tmp/dbus-XXXX`
# is what dbus-launch and dbus-run-session produce from the stock session.conf;
# `unix:path=/run/user/1000/bus` is a systemd login session, i.e. a real desktop.
#
# Two separate expressions rather than `\(path\|abstract\)`: `\|` alternation in
# a basic regex is a GNU extension, so that form silently matches NOTHING under
# BSD sed and the script would refuse every address on a Mac.
socket="$(printf '%s' "$DBUS_SESSION_BUS_ADDRESS" \
  | tr ',' '\n' \
  | sed -n -e 's/^unix:path=//p' -e 's/^unix:abstract=//p' \
  | head -n 1)"

if [ -z "$socket" ]; then
  echo "provision-disposable-keyring: unrecognized D-Bus address '$DBUS_SESSION_BUS_ADDRESS'" >&2
  exit 1
fi

case "$socket" in
  /tmp/* | "${RUNNER_TEMP:-/nonexistent}"/* | "${TMPDIR:-/nonexistent}"/*) ;;
  *)
    echo "provision-disposable-keyring: session bus socket '$socket' is not a throwaway bus under a temp root." >&2
    echo "  This looks like a login-session bus, whose keyring belongs to a human. Refusing." >&2
    exit 1
    ;;
esac

if ! command -v secret-tool >/dev/null 2>&1; then
  echo "provision-disposable-keyring: secret-tool is not installed" >&2
  exit 1
fi

# 32 bytes -> 64 hex characters. real-backend-guard.ts rejects any other length.
nonce="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"

printf '%s' "$nonce" | secret-tool store --label="Sanctuary CI disposable keyring probe" \
  service "$PROBE_SERVICE" account "$PROBE_ACCOUNT"

read_back="$(secret-tool lookup service "$PROBE_SERVICE" account "$PROBE_ACCOUNT" || true)"
if [ "$read_back" != "$nonce" ]; then
  echo "provision-disposable-keyring: nonce did not survive a store/lookup round trip; the Secret Service on this bus is not usable" >&2
  exit 1
fi

token_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
token_path="$token_dir/sanctuary-disposable-keyring.json"

# `%s` is whole seconds; the literal 000 appends the millisecond digits the
# guard's freshness bound expects. Sub-second precision is irrelevant against a
# six-hour window, and this avoids GNU-vs-BSD `date +%N` portability.
created_at_ms="$(date +%s000)"
umask 077
cat > "$token_path" <<EOF
{
  "nonce": "$nonce",
  "dbusAddress": "$DBUS_SESSION_BUS_ADDRESS",
  "createdAtMs": $created_at_ms
}
EOF
chmod 600 "$token_path"

echo "$token_path"
