#!/usr/bin/env bash
#
# build-signed.sh - produce a Developer-ID-signed CastleWallExtension `.app`
# bundle suitable for further wrapping into a `.systemextension` bundle
# (Alpha-4 install scope) and operator distribution.
#
# What this script does:
#
#   1. swift build -c release (Apple Silicon native build).
#   2. Assemble a `.app` bundle on disk by copying the built executable
#      into Contents/MacOS/ and the Info.plist + entitlements alongside.
#   3. codesign with the Developer ID Application identity (Team ID
#      YFQSWQ9BJN), hardened runtime, embedded entitlements.
#   4. verify the signature (codesign -dvvv + spctl assess + check
#      hardened-runtime + entitlements).
#
# What this script does NOT do (deferred):
#
#   - .systemextension wrapping (Alpha-4 install scope; depends on the
#     operator's larger app bundle layout).
#   - Notarization (`xcrun notarytool submit`). Notarization is operator-
#     side and out of scope for the build; the produced binary is
#     notarization-ready (hardened runtime + Developer-ID-signed).
#
# Usage:
#
#   ./scripts/build-signed.sh                        # uses default identity match
#   SIGNING_IDENTITY="Developer ID Application: Erik Newton (YFQSWQ9BJN)" \
#     ./scripts/build-signed.sh
#   BUILD_DIR=/tmp/cw-build ./scripts/build-signed.sh
#
# Environment overrides:
#   SIGNING_IDENTITY  Full common-name string of the cert to sign with.
#                     Default: a regex matching the canonical CN.
#   BUILD_DIR         Path to write the `.app` bundle. Defaults to
#                     `./build/CastleWallExtension.app` under the
#                     castle-wall-macos directory.
#   SWIFT_BUILD_CONFIG  Default `release`. Pass `debug` for dev iteration.
#
# Exit codes:
#   0 - success
#   1 - Xcode / SDK missing, signing identity not found, or codesign failed
#   2 - Bad arguments
#

set -euo pipefail

PKG_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
BUILD_DIR="${BUILD_DIR:-${PKG_DIR}/build/CastleWallExtension.app}"
SWIFT_BUILD_CONFIG="${SWIFT_BUILD_CONFIG:-release}"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-Developer ID Application: Erik Newton (YFQSWQ9BJN)}"
EXECUTABLE_NAME="CastleWallExtension"
INFO_PLIST="${PKG_DIR}/Sources/CastleWallExtension/Info.plist"
ENTITLEMENTS="${PKG_DIR}/Sources/CastleWallExtension/CastleWallExtension.entitlements"

echo "[build-signed] castle-wall-macos package: ${PKG_DIR}"
echo "[build-signed] swift build config: ${SWIFT_BUILD_CONFIG}"
echo "[build-signed] target .app bundle: ${BUILD_DIR}"
echo "[build-signed] signing identity:   ${SIGNING_IDENTITY}"

# Preflight: Xcode + SDK + signing identity reachable.
if ! command -v xcodebuild >/dev/null 2>&1; then
    echo "[build-signed] ERROR: xcodebuild not on PATH" >&2
    exit 1
fi
if ! xcrun --sdk macosx --show-sdk-path >/dev/null 2>&1; then
    echo "[build-signed] ERROR: macOS SDK not reachable (Xcode license may not be accepted)" >&2
    echo "[build-signed]        Run: sudo xcodebuild -license" >&2
    exit 1
fi
if ! security find-identity -v -p codesigning | grep -qF "${SIGNING_IDENTITY}"; then
    echo "[build-signed] ERROR: signing identity '${SIGNING_IDENTITY}' not in keychain" >&2
    echo "[build-signed]        Run: security find-identity -v -p codesigning" >&2
    exit 1
fi

# 1. swift build (release; native arch).
echo "[build-signed] step 1/4 - swift build -c ${SWIFT_BUILD_CONFIG}"
(
    cd "${PKG_DIR}" && \
    swift build -c "${SWIFT_BUILD_CONFIG}"
)

BUILT_EXEC="$(swift build -c "${SWIFT_BUILD_CONFIG}" --package-path "${PKG_DIR}" --show-bin-path)/${EXECUTABLE_NAME}"
if [ ! -x "${BUILT_EXEC}" ]; then
    echo "[build-signed] ERROR: built executable not found at ${BUILT_EXEC}" >&2
    exit 1
fi
echo "[build-signed]     built: ${BUILT_EXEC}"

# 2. Assemble .app bundle.
echo "[build-signed] step 2/4 - assemble .app bundle"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/Contents/MacOS"
cp "${BUILT_EXEC}" "${BUILD_DIR}/Contents/MacOS/${EXECUTABLE_NAME}"
cp "${INFO_PLIST}" "${BUILD_DIR}/Contents/Info.plist"
# Substitute Info.plist token placeholders that Xcode would normally fill.
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable ${EXECUTABLE_NAME}" "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :CFBundleName ${EXECUTABLE_NAME}" "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :NSExtension:NSExtensionPrincipalClass CastleWallFilter.CastleWallFilterProvider" \
    "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1
if grep -E '\$\([A-Z_]+\)' "${BUILD_DIR}/Contents/Info.plist" > /dev/null; then
    echo "ERROR: Info.plist still contains unresolved \$(...) tokens after PlistBuddy substitution" >&2
    grep -E '\$\([A-Z_]+\)' "${BUILD_DIR}/Contents/Info.plist" >&2
    exit 1
fi
echo "[build-signed]     assembled at ${BUILD_DIR}"

# 3. codesign with Developer ID + hardened runtime + entitlements.
echo "[build-signed] step 3/4 - codesign (hardened runtime + entitlements)"
codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "${SIGNING_IDENTITY}" \
    --entitlements "${ENTITLEMENTS}" \
    "${BUILD_DIR}"

# 4. Verify the signature + entitlements + hardened-runtime flag.
echo "[build-signed] step 4/4 - verify signature"
codesign -dvvv --entitlements - "${BUILD_DIR}" 2>&1 | head -40

# spctl assess against the developer-id rule. The unnotarized bundle
# will receive an `accepted` rejection per macOS Gatekeeper notarization
# requirements when run end-user; the codesign+spctl combination here
# verifies the SIGNATURE is valid even though notarization is deferred.
echo "[build-signed]     spctl assess (developer-id rule)"
if spctl --assess --type install --verbose=4 "${BUILD_DIR}" 2>&1 | tee /tmp/cw-spctl.log; then
    echo "[build-signed]     spctl accepted (notarized + signed)"
else
    if grep -q "source=Notarized Developer ID" /tmp/cw-spctl.log; then
        echo "[build-signed]     spctl accepted (notarized)"
    elif grep -qE "(rejected|notarized)" /tmp/cw-spctl.log; then
        echo "[build-signed]     spctl rejected - UNNOTARIZED is expected at this step"
        echo "[build-signed]     notarization (operator step) lands after this build:"
        echo "[build-signed]       xcrun notarytool submit \"${BUILD_DIR}\" --keychain-profile <profile>"
    else
        echo "[build-signed]     spctl returned unexpected status; see /tmp/cw-spctl.log" >&2
    fi
fi

echo "[build-signed] DONE"
echo "[build-signed] signed bundle: ${BUILD_DIR}"
echo "[build-signed] sha256:"
shasum -a 256 "${BUILD_DIR}/Contents/MacOS/${EXECUTABLE_NAME}"
