#!/usr/bin/env bash
#
# test-wrap-structure.sh - assertions for wrapped host app + nested
# .systemextension structure.
#

set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
WRAPPED_APP_DIR="${WRAPPED_APP_DIR:-${PKG_DIR}/build/Sanctuary-CastleWall.app}"

HOST_EXEC="${WRAPPED_APP_DIR}/Contents/MacOS/CastleWallHostApp"
HOST_INFO="${WRAPPED_APP_DIR}/Contents/Info.plist"
EXT_BUNDLE_ID="ai.sanctuaryprotocol.macos.castle-wall"
EXT_DIRNAME="${EXT_BUNDLE_ID}.systemextension"
EXT_BUNDLE="${WRAPPED_APP_DIR}/Contents/Library/SystemExtensions/${EXT_DIRNAME}"
EXT_EXEC="${EXT_BUNDLE}/Contents/MacOS/CastleWallExtension"
EXT_INFO="${EXT_BUNDLE}/Contents/Info.plist"
BOOT_RUNTIME_DIR="${WRAPPED_APP_DIR}/Contents/Resources/boot-runtime"
BOOT_RUNTIME_NODE="${BOOT_RUNTIME_DIR}/node"
BOOT_RUNTIME_DAEMON="${BOOT_RUNTIME_DIR}/castle-wall-boot-daemon.js"

log() {
    echo "[test-wrap-structure] $*"
}

fail() {
    echo "[test-wrap-structure] ERROR: $*" >&2
    exit 1
}

assert_exists() {
    local path="$1"
    [ -e "${path}" ] || fail "missing expected path: ${path}"
}

assert_macho() {
    local path="$1"
    file "${path}" | grep -q "Mach-O" || fail "expected Mach-O executable: ${path}"
}

assert_plist() {
    local path="$1"
    plutil -lint "${path}" >/dev/null || fail "invalid plist: ${path}"
}

log "running wrapped build script"
bash "${PKG_DIR}/scripts/build-wrapped.sh"

log "checking expected layout"
assert_exists "${WRAPPED_APP_DIR}"
assert_exists "${WRAPPED_APP_DIR}/Contents"
assert_exists "${WRAPPED_APP_DIR}/Contents/MacOS"
assert_exists "${WRAPPED_APP_DIR}/Contents/Library"
assert_exists "${WRAPPED_APP_DIR}/Contents/Library/SystemExtensions"
assert_exists "${HOST_EXEC}"
assert_exists "${HOST_INFO}"
assert_exists "${EXT_BUNDLE}"
assert_exists "${EXT_EXEC}"
assert_exists "${EXT_INFO}"

if [ "${SANCTUARY_REQUIRE_BOOT_RUNTIME:-0}" = "1" ]; then
    log "checking sealed boot-runtime layout"
    assert_exists "${BOOT_RUNTIME_NODE}"
    assert_exists "${BOOT_RUNTIME_DAEMON}"
    [ -x "${BOOT_RUNTIME_NODE}" ] || fail "boot-runtime node is not executable: ${BOOT_RUNTIME_NODE}"
    [ -s "${BOOT_RUNTIME_DAEMON}" ] || fail "boot-runtime daemon is empty: ${BOOT_RUNTIME_DAEMON}"
    [ "$(stat -f '%Lp' "${BOOT_RUNTIME_NODE}")" = "555" ] || fail "boot-runtime node mode is not 0555"
    [ "$(stat -f '%Lp' "${BOOT_RUNTIME_DAEMON}")" = "444" ] || fail "boot-runtime daemon mode is not 0444"
fi

log "checking Mach-O binaries"
assert_macho "${HOST_EXEC}"
assert_macho "${EXT_EXEC}"
if [ "${SANCTUARY_REQUIRE_BOOT_RUNTIME:-0}" = "1" ]; then
    assert_macho "${BOOT_RUNTIME_NODE}"
fi

log "checking plist validity"
assert_plist "${HOST_INFO}"
assert_plist "${EXT_INFO}"

log "verifying code signature"
codesign --verify --deep --strict "${WRAPPED_APP_DIR}" || fail "codesign verify failed"

log "checking extension bundle id"
ACTUAL_BUNDLE_ID="$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "${EXT_INFO}")"
[ "${ACTUAL_BUNDLE_ID}" = "${EXT_BUNDLE_ID}" ] || fail "unexpected extension bundle id: ${ACTUAL_BUNDLE_ID}"

log "all checks passed"
