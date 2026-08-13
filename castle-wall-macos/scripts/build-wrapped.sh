#!/usr/bin/env bash
#
# build-wrapped.sh - assemble a host `.app` bundle with a nested
# `.systemextension` bundle for Castle Wall.
#
# This script is intentionally tolerant of an in-flight repository state where
# `CastleWallHostApp` may not be present yet. In that case it uses the
# extension Mach-O as a temporary host executable stand-in.
#

set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
REPO_DIR="$(cd "${PKG_DIR}/.." && pwd)"
SWIFT_BUILD_CONFIG="${SWIFT_BUILD_CONFIG:-release}"
BUILD_ROOT="${BUILD_ROOT:-${PKG_DIR}/build}"
WRAPPED_APP_DIR="${WRAPPED_APP_DIR:-${BUILD_ROOT}/Sanctuary-CastleWall.app}"
CASTLE_WALL_GIT_SHA="${CASTLE_WALL_GIT_SHA:-$(git -C "${REPO_DIR}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
# Monotonic CFBundleVersion: macOS only replaces an activated system extension
# when the version increases. A hardcoded version means rebuilt fixes never load
# (root-caused on the 2026-06-11b W5 drill). git commit count is monotonic.
CASTLE_WALL_BUNDLE_VERSION="${CASTLE_WALL_BUNDLE_VERSION:-$(git -C "${REPO_DIR}" rev-list --count HEAD 2>/dev/null || echo 10)}"
CASTLE_WALL_HEADLESS_CONTRACT_VERSION="${CASTLE_WALL_HEADLESS_CONTRACT_VERSION:-3}"

HOST_TARGET="CastleWallHostApp"
HOST_EXECUTABLE_NAME="CastleWallHostApp"
HOST_INFO_SRC="${PKG_DIR}/Sources/CastleWallHostApp/Info.plist"

EXT_TARGET="CastleWallExtension"
EXT_EXECUTABLE_NAME="CastleWallExtension"
EXT_INFO_SRC="${PKG_DIR}/Sources/CastleWallExtension/Info.plist"
EXT_BUNDLE_ID="ai.sanctuaryprotocol.macos.castle-wall"

SYSTEM_EXTENSION_DIRNAME="${EXT_BUNDLE_ID}.systemextension"

HOST_EXEC_DST="${WRAPPED_APP_DIR}/Contents/MacOS/${HOST_EXECUTABLE_NAME}"
HOST_INFO_DST="${WRAPPED_APP_DIR}/Contents/Info.plist"
EXT_BUNDLE_DST="${WRAPPED_APP_DIR}/Contents/Library/SystemExtensions/${SYSTEM_EXTENSION_DIRNAME}"
EXT_EXEC_DST="${EXT_BUNDLE_DST}/Contents/MacOS/${EXT_EXECUTABLE_NAME}"
EXT_INFO_DST="${EXT_BUNDLE_DST}/Contents/Info.plist"

# A2/B2 root signer helper + XPC shim + LaunchDaemon plist. The helper binary is
# placed in Contents/MacOS with the on-disk name the plist BundleProgram expects.
SIGNER_HELPER_EXE_NAME="CastleWallSignerHelper"
SIGNER_HELPER_DST="${WRAPPED_APP_DIR}/Contents/MacOS/castle-wall-signer-helper"
SIGNER_CLIENT_EXE_NAME="CastleWallSignerClient"
SIGNER_CLIENT_DST="${WRAPPED_APP_DIR}/Contents/MacOS/castle-wall-signer-client"
SIGNER_PLIST_SRC="${PKG_DIR}/Sources/CastleWallSignerHelper/ai.sanctuaryprotocol.macos.castle-wall.signer-helper.plist"
SIGNER_PLIST_DST="${WRAPPED_APP_DIR}/Contents/Library/LaunchDaemons/ai.sanctuaryprotocol.macos.castle-wall.signer-helper.plist"

# The root Castle Wall boot service snapshots these exact app-bundled assets
# into root-owned custody. They must come from the same signed/notarized app as
# the signer client, never from the operator's mutable Homebrew installation.
BOOT_RUNTIME_DIR="${WRAPPED_APP_DIR}/Contents/Resources/boot-runtime"
BOOT_RUNTIME_NODE_SRC="${SANCTUARY_BOOT_RUNTIME_NODE:-}"
BOOT_RUNTIME_DAEMON_SRC="${SANCTUARY_BOOT_RUNTIME_DAEMON:-${REPO_DIR}/server/dist/boot-runtime/castle-wall-boot-daemon.js}"
REQUIRE_BOOT_RUNTIME="${SANCTUARY_REQUIRE_BOOT_RUNTIME:-0}"

log() {
    echo "[build-wrapped] $*"
}

fail() {
    echo "[build-wrapped] ERROR: $*" >&2
    exit 1
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "required command not found on PATH: $1"
    fi
}

target_exists() {
    local target="$1"
    grep -q "name: \"${target}\"" "${PKG_DIR}/Package.swift"
}

generate_minimal_host_info_plist() {
    cat > "${HOST_INFO_DST}" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>CastleWallHostApp</string>
    <key>CFBundleIdentifier</key>
    <string>ai.sanctuaryprotocol.macos.castle-wall.host</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Sanctuary-CastleWall</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>0.1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
</dict>
</plist>
EOF
}

require_cmd swift
require_cmd plutil
require_cmd file
require_cmd codesign
require_cmd /usr/libexec/PlistBuddy

log "castle-wall-macos package: ${PKG_DIR}"
log "swift build config: ${SWIFT_BUILD_CONFIG}"
log "git sha: ${CASTLE_WALL_GIT_SHA}"
log "headless contract: ${CASTLE_WALL_HEADLESS_CONTRACT_VERSION}"
log "wrapped app target: ${WRAPPED_APP_DIR}"

log "step 1/5 - build release artifacts"
(
    cd "${PKG_DIR}"
    # Build ALL products in one pass. `swift build --target <exe>` does not
    # reliably materialize an executable target's top-level binary into the bin
    # dir; a full product build does. All targets (ext, host, signer helper +
    # shim) compile, so a single build is both correct and simpler.
    if target_exists "${HOST_TARGET}"; then
        swift build -c "${SWIFT_BUILD_CONFIG}"
    else
        log "target '${HOST_TARGET}' not present yet; building extension only"
        swift build -c "${SWIFT_BUILD_CONFIG}" --target "${EXT_TARGET}"
    fi
)

BIN_DIR="$(swift build -c "${SWIFT_BUILD_CONFIG}" --package-path "${PKG_DIR}" --show-bin-path)"
EXT_EXEC_SRC="${BIN_DIR}/${EXT_EXECUTABLE_NAME}"
HOST_EXEC_SRC="${BIN_DIR}/${HOST_EXECUTABLE_NAME}"
SIGNER_HELPER_SRC="${BIN_DIR}/${SIGNER_HELPER_EXE_NAME}"
SIGNER_CLIENT_SRC="${BIN_DIR}/${SIGNER_CLIENT_EXE_NAME}"

[ -x "${EXT_EXEC_SRC}" ] || fail "extension executable not found at ${EXT_EXEC_SRC}"

log "step 2/5 - create wrapped bundle layout"
rm -rf "${WRAPPED_APP_DIR}"
mkdir -p "$(dirname "${HOST_EXEC_DST}")"
mkdir -p "$(dirname "${EXT_EXEC_DST}")"

cp "${EXT_EXEC_SRC}" "${EXT_EXEC_DST}"
if [ -x "${HOST_EXEC_SRC}" ]; then
    cp "${HOST_EXEC_SRC}" "${HOST_EXEC_DST}"
else
    cp "${EXT_EXEC_SRC}" "${HOST_EXEC_DST}"
fi
chmod +x "${HOST_EXEC_DST}" "${EXT_EXEC_DST}"

# Bundle the A2/B2 signer helper + shim + LaunchDaemon plist when present.
if [ -x "${SIGNER_HELPER_SRC}" ] && [ -x "${SIGNER_CLIENT_SRC}" ]; then
    log "bundling signer helper + shim + LaunchDaemon plist"
    mkdir -p "$(dirname "${SIGNER_PLIST_DST}")"
    cp "${SIGNER_HELPER_SRC}" "${SIGNER_HELPER_DST}"
    cp "${SIGNER_CLIENT_SRC}" "${SIGNER_CLIENT_DST}"
    chmod +x "${SIGNER_HELPER_DST}" "${SIGNER_CLIENT_DST}"
    cp "${SIGNER_PLIST_SRC}" "${SIGNER_PLIST_DST}"
    plutil -lint "${SIGNER_PLIST_DST}" >/dev/null || fail "signer LaunchDaemon plist failed lint"
else
    log "signer helper/shim binaries not built; LaunchDaemon not bundled (pre-A2 layout)"
fi

if [ -n "${BOOT_RUNTIME_NODE_SRC}" ] && [ -x "${BOOT_RUNTIME_NODE_SRC}" ] && [ -f "${BOOT_RUNTIME_DAEMON_SRC}" ]; then
    log "bundling sealed Castle Wall boot runtime"
    mkdir -p "${BOOT_RUNTIME_DIR}"
    cp "${BOOT_RUNTIME_NODE_SRC}" "${BOOT_RUNTIME_DIR}/node"
    cp "${BOOT_RUNTIME_DAEMON_SRC}" "${BOOT_RUNTIME_DIR}/castle-wall-boot-daemon.js"
    chmod 0555 "${BOOT_RUNTIME_DIR}/node"
    chmod 0444 "${BOOT_RUNTIME_DIR}/castle-wall-boot-daemon.js"
elif [ "${REQUIRE_BOOT_RUNTIME}" = "1" ]; then
    fail "signed build requires SANCTUARY_BOOT_RUNTIME_NODE and built ${BOOT_RUNTIME_DAEMON_SRC}"
else
    log "boot runtime inputs absent; omitted from this non-release wrapped build"
fi

log "step 3/5 - install Info.plist files"
if [ -f "${HOST_INFO_SRC}" ]; then
    cp "${HOST_INFO_SRC}" "${HOST_INFO_DST}"
else
    generate_minimal_host_info_plist
fi
cp "${EXT_INFO_SRC}" "${EXT_INFO_DST}"

/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable ${HOST_EXECUTABLE_NAME}" "${HOST_INFO_DST}" >/dev/null 2>&1 || true
/usr/libexec/PlistBuddy -c "Set :CFBundleName Sanctuary-CastleWall" "${HOST_INFO_DST}" >/dev/null 2>&1 || true
/usr/libexec/PlistBuddy -c "Set :SanctuaryCastleWallGitSHA ${CASTLE_WALL_GIT_SHA}" "${HOST_INFO_DST}" >/dev/null 2>&1 || \
    /usr/libexec/PlistBuddy -c "Add :SanctuaryCastleWallGitSHA string ${CASTLE_WALL_GIT_SHA}" "${HOST_INFO_DST}" >/dev/null
/usr/libexec/PlistBuddy -c "Set :SanctuaryCastleWallHeadlessContractVersion ${CASTLE_WALL_HEADLESS_CONTRACT_VERSION}" "${HOST_INFO_DST}" >/dev/null 2>&1 || \
    /usr/libexec/PlistBuddy -c "Add :SanctuaryCastleWallHeadlessContractVersion string ${CASTLE_WALL_HEADLESS_CONTRACT_VERSION}" "${HOST_INFO_DST}" >/dev/null
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable ${EXT_EXECUTABLE_NAME}" "${EXT_INFO_DST}" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :CFBundleName ${EXT_EXECUTABLE_NAME}" "${EXT_INFO_DST}" >/dev/null 2>&1
# Bump the extension AND host CFBundleVersion so macOS replaces the activated sysext.
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${CASTLE_WALL_BUNDLE_VERSION}" "${EXT_INFO_DST}" >/dev/null 2>&1 || \
    /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string ${CASTLE_WALL_BUNDLE_VERSION}" "${EXT_INFO_DST}" >/dev/null
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${CASTLE_WALL_BUNDLE_VERSION}" "${HOST_INFO_DST}" >/dev/null 2>&1 || \
    /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string ${CASTLE_WALL_BUNDLE_VERSION}" "${HOST_INFO_DST}" >/dev/null
/usr/libexec/PlistBuddy -c "Set :NSExtension:NSExtensionPrincipalClass CastleWallFilterProvider" "${EXT_INFO_DST}" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :NetworkExtension:NEProviderClasses:com.apple.networkextension.filter-data CastleWallFilterProvider" "${EXT_INFO_DST}" >/dev/null 2>&1

if grep -E '\$\([A-Z_]+\)' "${HOST_INFO_DST}" >/dev/null 2>&1; then
    fail "host Info.plist contains unresolved \$(...) tokens: ${HOST_INFO_DST}"
fi
if grep -E '\$\([A-Z_]+\)' "${EXT_INFO_DST}" >/dev/null 2>&1; then
    fail "extension Info.plist contains unresolved \$(...) tokens: ${EXT_INFO_DST}"
fi

log "step 4/5 - ad-hoc sign nested extension, signer helper/shim, then outer host app"
codesign --force --sign - --timestamp=none "${EXT_BUNDLE_DST}"
if [ -x "${SIGNER_HELPER_DST}" ] && [ -x "${SIGNER_CLIENT_DST}" ]; then
    # Ad-hoc with pinned identifiers so the structure mirrors the Dev-ID build;
    # the real Developer-ID signing (with entitlements) happens in build-signed.sh.
    codesign --force --sign - --timestamp=none \
        --identifier ai.sanctuaryprotocol.macos.castle-wall.signer-helper \
        "${SIGNER_HELPER_DST}"
    codesign --force --sign - --timestamp=none \
        --identifier ai.sanctuaryprotocol.macos.castle-wall.signer-client \
        "${SIGNER_CLIENT_DST}"
fi
codesign --force --sign - --timestamp=none "${WRAPPED_APP_DIR}"

log "step 5/5 - verify structure and signatures"
plutil -lint "${HOST_INFO_DST}"
plutil -lint "${EXT_INFO_DST}"
file "${HOST_EXEC_DST}" | grep -q "Mach-O" || fail "host executable is not Mach-O: ${HOST_EXEC_DST}"
file "${EXT_EXEC_DST}" | grep -q "Mach-O" || fail "extension executable is not Mach-O: ${EXT_EXEC_DST}"
codesign --verify --deep --strict "${WRAPPED_APP_DIR}"

log "bundle tree:"
find "${WRAPPED_APP_DIR}" -print
log "DONE"
