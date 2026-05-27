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
SWIFT_BUILD_CONFIG="${SWIFT_BUILD_CONFIG:-release}"
BUILD_ROOT="${BUILD_ROOT:-${PKG_DIR}/build}"
WRAPPED_APP_DIR="${WRAPPED_APP_DIR:-${BUILD_ROOT}/Sanctuary-CastleWall.app}"

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
log "wrapped app target: ${WRAPPED_APP_DIR}"

log "step 1/5 - build release artifacts"
(
    cd "${PKG_DIR}"
    swift build -c "${SWIFT_BUILD_CONFIG}" --target "${EXT_TARGET}"
    if target_exists "${HOST_TARGET}"; then
        log "detected target '${HOST_TARGET}', building host target"
        swift build -c "${SWIFT_BUILD_CONFIG}" --target "${HOST_TARGET}"
    else
        log "target '${HOST_TARGET}' not present yet; using fallback host executable"
    fi
)

BIN_DIR="$(swift build -c "${SWIFT_BUILD_CONFIG}" --package-path "${PKG_DIR}" --show-bin-path)"
EXT_EXEC_SRC="${BIN_DIR}/${EXT_EXECUTABLE_NAME}"
HOST_EXEC_SRC="${BIN_DIR}/${HOST_EXECUTABLE_NAME}"

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

log "step 3/5 - install Info.plist files"
if [ -f "${HOST_INFO_SRC}" ]; then
    cp "${HOST_INFO_SRC}" "${HOST_INFO_DST}"
else
    generate_minimal_host_info_plist
fi
cp "${EXT_INFO_SRC}" "${EXT_INFO_DST}"

/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable ${HOST_EXECUTABLE_NAME}" "${HOST_INFO_DST}" >/dev/null 2>&1 || true
/usr/libexec/PlistBuddy -c "Set :CFBundleName Sanctuary-CastleWall" "${HOST_INFO_DST}" >/dev/null 2>&1 || true
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable ${EXT_EXECUTABLE_NAME}" "${EXT_INFO_DST}" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :CFBundleName ${EXT_EXECUTABLE_NAME}" "${EXT_INFO_DST}" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :NSExtension:NSExtensionPrincipalClass CastleWallFilterProvider" "${EXT_INFO_DST}" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :NetworkExtension:NEProviderClasses:com.apple.networkextension.filter-data CastleWallFilterProvider" "${EXT_INFO_DST}" >/dev/null 2>&1

if grep -E '\$\([A-Z_]+\)' "${HOST_INFO_DST}" >/dev/null 2>&1; then
    fail "host Info.plist contains unresolved \$(...) tokens: ${HOST_INFO_DST}"
fi
if grep -E '\$\([A-Z_]+\)' "${EXT_INFO_DST}" >/dev/null 2>&1; then
    fail "extension Info.plist contains unresolved \$(...) tokens: ${EXT_INFO_DST}"
fi

log "step 4/5 - ad-hoc sign nested extension then outer host app"
codesign --force --sign - --timestamp=none "${EXT_BUNDLE_DST}"
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
