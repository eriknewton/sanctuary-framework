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
#   ./scripts/build-signed.sh --wrapped              # also assemble/sign outer host .app
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
REPO_DIR="$(cd "${PKG_DIR}/.." && pwd)"
BUILD_DIR="${BUILD_DIR:-${PKG_DIR}/build/CastleWallExtension.app}"
SWIFT_BUILD_CONFIG="${SWIFT_BUILD_CONFIG:-release}"
SIGNING_IDENTITY="${SIGNING_IDENTITY:-Developer ID Application: Erik Newton (YFQSWQ9BJN)}"
CASTLE_WALL_GIT_SHA="${CASTLE_WALL_GIT_SHA:-$(git -C "${REPO_DIR}" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)}"
CASTLE_WALL_SOURCE_SHA="${CASTLE_WALL_SOURCE_SHA:-$(git -C "${REPO_DIR}" rev-parse HEAD 2>/dev/null || echo unknown)}"
SANCTUARY_PACKAGE_VERSION="${SANCTUARY_PACKAGE_VERSION:-$(node -p "require('${REPO_DIR}/server/package.json').version")}"
# CFBundleVersion MUST increase whenever the extension code changes, or macOS
# treats a rebuilt sysext as the same version and KEEPS the already-activated
# (stale) extension binary — silently shipping the old enforcement code. The
# git commit count is monotonic per commit, so every merged fix bumps it.
# (Root-caused on the 2026-06-11b W5 drill: a W5-fixed app deployed but the
# pre-W5 extension stayed active because the hardcoded version 10 never moved.)
CASTLE_WALL_BUNDLE_VERSION="${CASTLE_WALL_BUNDLE_VERSION:-$(git -C "${REPO_DIR}" rev-list --count HEAD 2>/dev/null || echo 10)}"
CASTLE_WALL_HEADLESS_CONTRACT_VERSION="${CASTLE_WALL_HEADLESS_CONTRACT_VERSION:-3}"
EXECUTABLE_NAME="CastleWallExtension"
INFO_PLIST="${PKG_DIR}/Sources/CastleWallExtension/Info.plist"
ENTITLEMENTS="${PKG_DIR}/Sources/CastleWallExtension/CastleWallExtension.entitlements"
HOST_ENTITLEMENTS="${PKG_DIR}/Sources/CastleWallHostApp/CastleWallHostApp.entitlements"
# Provisioning profiles for the restricted entitlements. Resolution order:
# explicit env override, then the operator's ~/Documents copy (legacy local
# layout), then the repo-committed copies under signing/. The repo copies are
# NOT secrets: a provisioning profile ships inside every distributed app at
# Contents/embedded.provisionprofile, readable by anyone who downloads the
# release zip. It contains only public certificate data and the entitlement
# grant; it cannot sign anything. Committing it is what lets CI produce a
# launchable bundle (the v1.7.0/v1.7.1 CI builds omitted it and AMFI refused
# to spawn them).
REPO_PROVISIONING_PROFILE="${PKG_DIR}/signing/castle-wall-devid.provisionprofile"
REPO_EXT_PROVISIONING_PROFILE="${PKG_DIR}/signing/castle-wall-extension-devid.provisionprofile"
if [ -z "${PROVISIONING_PROFILE:-}" ]; then
    if [ -f "${HOME}/Documents/Sanctuary_Castle_Wall_macOS.provisionprofile" ]; then
        PROVISIONING_PROFILE="${HOME}/Documents/Sanctuary_Castle_Wall_macOS.provisionprofile"
    else
        PROVISIONING_PROFILE="${REPO_PROVISIONING_PROFILE}"
    fi
fi
if [ -z "${EXT_PROVISIONING_PROFILE:-}" ]; then
    if [ -f "${HOME}/Documents/Sanctuary_Castle_Wall_Extension.provisionprofile" ]; then
        EXT_PROVISIONING_PROFILE="${HOME}/Documents/Sanctuary_Castle_Wall_Extension.provisionprofile"
    else
        EXT_PROVISIONING_PROFILE="${REPO_EXT_PROVISIONING_PROFILE}"
    fi
fi
WRAPPED=false
ALLOW_UNNOTARIZED=false
WRAPPED_APP_DIR="${WRAPPED_APP_DIR:-${PKG_DIR}/build/Sanctuary-CastleWall.app}"
SYSTEM_EXTENSION_DIRNAME="ai.sanctuaryprotocol.macos.castle-wall.systemextension"

# A2/B2 signer helper + shim. Pinned designated identifiers (the helper's caller
# requirement checks the shim's identifier — Sources/CastleWallSigner/CodeRequirement.swift).
SIGNER_HELPER_ID="ai.sanctuaryprotocol.macos.castle-wall.signer-helper"
SIGNER_CLIENT_ID="ai.sanctuaryprotocol.macos.castle-wall.signer-client"
SIGNER_HELPER_DST="${WRAPPED_APP_DIR}/Contents/MacOS/castle-wall-signer-helper"
SIGNER_CLIENT_DST="${WRAPPED_APP_DIR}/Contents/MacOS/castle-wall-signer-client"
SIGNER_HELPER_ENTITLEMENTS="${PKG_DIR}/Sources/CastleWallSignerHelper/CastleWallSignerHelper.entitlements"
SIGNER_CLIENT_ENTITLEMENTS="${PKG_DIR}/Sources/CastleWallSignerClient/CastleWallSignerClient.entitlements"
BOOT_RUNTIME_NODE_ENTITLEMENTS="${PKG_DIR}/signing/node-boot-runtime.entitlements"
SANCTUARY_LAUNCHER_ID="ai.sanctuaryprotocol.macos.castle-wall.sanctuary-launcher"
SANCTUARY_LAUNCHER_DST="${WRAPPED_APP_DIR}/Contents/MacOS/sanctuary"
CLI_RUNTIME_MANIFEST="${WRAPPED_APP_DIR}/Contents/Resources/cli-runtime-manifest.json"
CLI_RUNTIME_MACH_O_SCANNER="${PKG_DIR}/scripts/list-cli-runtime-mach-o.mjs"
# Notarization: set NOTARYTOOL_PROFILE (a `notarytool store-credentials` keychain
# profile) to notarize + staple automatically. Apps that bundle a LaunchDaemon
# MUST be notarized or SMAppService stays stuck at .requiresApproval/.notFound.
NOTARYTOOL_PROFILE="${NOTARYTOOL_PROFILE:-}"

usage() {
    cat <<EOF
Usage: $(basename "$0") [--wrapped]

Options:
  --wrapped            Assemble nested .systemextension host app and sign:
                       1) inner .systemextension
                       2) outer .app (deep sign)
  --allow-unnotarized  Permit a --wrapped build to finish without notarization.
                       For CI / local non-deploy builds ONLY. A sysext bundle
                       that is signed-but-unnotarized is silently uninstalled by
                       macOS (Tahoe sysextd) at validation with no replacement
                       prompt, so deploy builds MUST notarize (set NOTARYTOOL_PROFILE).
  -h, --help           Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --wrapped)
            WRAPPED=true
            shift
            ;;
        --allow-unnotarized)
            ALLOW_UNNOTARIZED=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[build-signed] ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

TOTAL_STEPS=4
if [ "${WRAPPED}" = true ]; then
    TOTAL_STEPS=5
fi

echo "[build-signed] castle-wall-macos package: ${PKG_DIR}"
echo "[build-signed] swift build config: ${SWIFT_BUILD_CONFIG}"
echo "[build-signed] git sha: ${CASTLE_WALL_GIT_SHA}"
echo "[build-signed] headless contract: ${CASTLE_WALL_HEADLESS_CONTRACT_VERSION}"
echo "[build-signed] target .app bundle: ${BUILD_DIR}"
echo "[build-signed] signing identity:   ${SIGNING_IDENTITY}"
echo "[build-signed] wrapped mode:        ${WRAPPED}"

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

# Preflight: keychain access for unattended codesign.
# This script signs multiple bundles in sequence (host app, system extension,
# wrapped nested app). codesign reaches into the login keychain for the
# Developer ID private key on every sign call, and without a partition-list
# grant macOS pops a "codesign wants to use key" dialog once per call. An
# autonomous build thread cannot click those dialogs, so the build appears to
# hang and the operator gets prompted repeatedly.
#
# The durable fix is a one-time operator grant (run interactively, password
# prompts, never lands in shell history):
#   security set-key-partition-list -S apple-tool:,apple:,codesign: -s \
#     "${HOME}/Library/Keychains/login.keychain-db"
#
# This block makes the build self-heal when SANCTUARY_KEYCHAIN_PW is exported
# for the session (re-asserts the grant + unlocks the keychain so a sleep/
# timeout lock does not reintroduce prompts). When the env var is not set, it
# verifies nothing and just advises, relying on the prior one-time grant.
SIGNING_KEYCHAIN="${SANCTUARY_SIGNING_KEYCHAIN:-${HOME}/Library/Keychains/login.keychain-db}"
if [ -n "${SANCTUARY_KEYCHAIN_PW:-}" ]; then
    echo "[build-signed] keychain preflight: unlock + assert partition list (SANCTUARY_KEYCHAIN_PW set)"
    if ! security unlock-keychain -p "${SANCTUARY_KEYCHAIN_PW}" "${SIGNING_KEYCHAIN}"; then
        echo "[build-signed] ERROR: keychain unlock failed (wrong SANCTUARY_KEYCHAIN_PW?)" >&2
        exit 1
    fi
    if ! security set-key-partition-list -S apple-tool:,apple:,codesign: -s \
            -k "${SANCTUARY_KEYCHAIN_PW}" "${SIGNING_KEYCHAIN}" >/dev/null 2>&1; then
        echo "[build-signed] WARN: set-key-partition-list returned non-zero; codesign may still prompt" >&2
    fi
else
    echo "[build-signed] keychain preflight: SANCTUARY_KEYCHAIN_PW not set; relying on prior one-time partition-list grant"
    echo "[build-signed]   If codesign prompts repeatedly, run ONCE (interactive; password prompts, not in history):"
    echo "[build-signed]     security set-key-partition-list -S apple-tool:,apple:,codesign: -s \"${SIGNING_KEYCHAIN}\""
    echo "[build-signed]   Or export SANCTUARY_KEYCHAIN_PW for this session so the build self-heals."
fi

# 1. swift build (release; native arch).
echo "[build-signed] step 1/${TOTAL_STEPS} - swift build -c ${SWIFT_BUILD_CONFIG}"
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
echo "[build-signed] step 2/${TOTAL_STEPS} - assemble .app bundle"
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/Contents/MacOS"
cp "${BUILT_EXEC}" "${BUILD_DIR}/Contents/MacOS/${EXECUTABLE_NAME}"
cp "${INFO_PLIST}" "${BUILD_DIR}/Contents/Info.plist"
# Substitute Info.plist token placeholders that Xcode would normally fill.
/usr/libexec/PlistBuddy -c "Set :CFBundleExecutable ${EXECUTABLE_NAME}" "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :CFBundleName ${EXECUTABLE_NAME}" "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :NSExtension:NSExtensionPrincipalClass CastleWallFilter.CastleWallFilterProvider" \
    "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1
/usr/libexec/PlistBuddy -c "Set :SanctuaryCastleWallGitSHA ${CASTLE_WALL_GIT_SHA}" \
    "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1 || \
    /usr/libexec/PlistBuddy -c "Add :SanctuaryCastleWallGitSHA string ${CASTLE_WALL_GIT_SHA}" \
        "${BUILD_DIR}/Contents/Info.plist" >/dev/null
# Monotonic CFBundleVersion so macOS sees a rebuilt extension as an update and
# replaces the activated binary (see CASTLE_WALL_BUNDLE_VERSION rationale above).
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion ${CASTLE_WALL_BUNDLE_VERSION}" \
    "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1 || \
    /usr/libexec/PlistBuddy -c "Add :CFBundleVersion string ${CASTLE_WALL_BUNDLE_VERSION}" \
        "${BUILD_DIR}/Contents/Info.plist" >/dev/null
/usr/libexec/PlistBuddy -c "Set :SanctuaryCastleWallHeadlessContractVersion ${CASTLE_WALL_HEADLESS_CONTRACT_VERSION}" \
    "${BUILD_DIR}/Contents/Info.plist" >/dev/null 2>&1 || \
    /usr/libexec/PlistBuddy -c "Add :SanctuaryCastleWallHeadlessContractVersion string ${CASTLE_WALL_HEADLESS_CONTRACT_VERSION}" \
        "${BUILD_DIR}/Contents/Info.plist" >/dev/null
if grep -E '\$\([A-Z_]+\)' "${BUILD_DIR}/Contents/Info.plist" > /dev/null; then
    echo "ERROR: Info.plist still contains unresolved \$(...) tokens after PlistBuddy substitution" >&2
    grep -E '\$\([A-Z_]+\)' "${BUILD_DIR}/Contents/Info.plist" >&2
    exit 1
fi
echo "[build-signed]     assembled at ${BUILD_DIR}"

# 3. codesign with Developer ID + hardened runtime + entitlements.
echo "[build-signed] step 3/${TOTAL_STEPS} - codesign (hardened runtime + entitlements)"
codesign \
    --force \
    --options runtime \
    --timestamp \
    --sign "${SIGNING_IDENTITY}" \
    --entitlements "${ENTITLEMENTS}" \
    "${BUILD_DIR}"

# 4. Verify the signature + entitlements + hardened-runtime flag.
echo "[build-signed] step 4/${TOTAL_STEPS} - verify signature"
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

if [ "${WRAPPED}" = true ]; then
    WRAPPED_SCRIPT="${PKG_DIR}/scripts/build-wrapped.sh"
    INNER_SYSTEM_EXTENSION="${WRAPPED_APP_DIR}/Contents/Library/SystemExtensions/${SYSTEM_EXTENSION_DIRNAME}"

    if [ ! -x "${WRAPPED_SCRIPT}" ]; then
        echo "[build-signed] ERROR: wrapped build script not executable: ${WRAPPED_SCRIPT}" >&2
        exit 1
    fi

    echo "[build-signed] step 5/${TOTAL_STEPS} - build wrapped app and sign inner->outer"
    SWIFT_BUILD_CONFIG="${SWIFT_BUILD_CONFIG}" \
    WRAPPED_APP_DIR="${WRAPPED_APP_DIR}" \
    bash "${WRAPPED_SCRIPT}"

    if [ ! -d "${INNER_SYSTEM_EXTENSION}" ]; then
        echo "[build-signed] ERROR: nested .systemextension missing at ${INNER_SYSTEM_EXTENSION}" >&2
        exit 1
    fi
    if [ ! -d "${WRAPPED_APP_DIR}" ]; then
        echo "[build-signed] ERROR: wrapped host app missing at ${WRAPPED_APP_DIR}" >&2
        exit 1
    fi

    # A wrapped bundle whose binaries claim restricted entitlements
    # (com.apple.developer.system-extension.install, networkextension
    # provider) but carry no embedded.provisionprofile is REFUSED BY AMFI at
    # spawn on every end-user Mac ("Launchd job spawn failed", RBS error 5).
    # The v1.7.0 and v1.7.1 release assets shipped exactly that way because
    # this branch used to warn and continue. A missing profile is therefore
    # fatal in wrapped mode: there is no configuration in which the output
    # would be launchable.
    if [ ! -f "${PROVISIONING_PROFILE}" ]; then
        echo "[build-signed] ERROR: host provisioning profile not found at ${PROVISIONING_PROFILE}" >&2
        echo "[build-signed]        A wrapped bundle without Contents/embedded.provisionprofile is" >&2
        echo "[build-signed]        killed by AMFI at spawn (restricted entitlements, no profile)." >&2
        echo "[build-signed]        Repo copy: ${REPO_PROVISIONING_PROFILE}; override with PROVISIONING_PROFILE=<path>." >&2
        exit 1
    fi
    if [ ! -f "${EXT_PROVISIONING_PROFILE}" ]; then
        echo "[build-signed] ERROR: extension provisioning profile not found at ${EXT_PROVISIONING_PROFILE}" >&2
        echo "[build-signed]        The nested .systemextension claims the content-filter provider" >&2
        echo "[build-signed]        entitlement and needs its own Contents/embedded.provisionprofile." >&2
        echo "[build-signed]        Repo copy: ${REPO_EXT_PROVISIONING_PROFILE}; override with EXT_PROVISIONING_PROFILE=<path>." >&2
        exit 1
    fi

    echo "[build-signed]     embedding provisioning profile (${PROVISIONING_PROFILE})"
    cp "${PROVISIONING_PROFILE}" "${WRAPPED_APP_DIR}/Contents/embedded.provisionprofile"
    # F2: profiles copied from ~/Documents carry com.apple.quarantine, which
    # survives into the signed sysext and causes a first-attempt
    # codeSignatureInvalid (SIP protects the files after signing, so it
    # cannot be stripped later). Strip it before signing; ignore if absent.
    xattr -d com.apple.quarantine "${WRAPPED_APP_DIR}/Contents/embedded.provisionprofile" 2>/dev/null || true

    echo "[build-signed]     embedding extension provisioning profile (${EXT_PROVISIONING_PROFILE})"
    cp "${EXT_PROVISIONING_PROFILE}" "${INNER_SYSTEM_EXTENSION}/Contents/embedded.provisionprofile"
    # F2: same quarantine strip for the extension profile (see above).
    xattr -d com.apple.quarantine "${INNER_SYSTEM_EXTENSION}/Contents/embedded.provisionprofile" 2>/dev/null || true

    echo "[build-signed]     signing inner .systemextension with Developer ID"
    codesign \
        --force \
        --options runtime \
        --timestamp \
        --sign "${SIGNING_IDENTITY}" \
        --entitlements "${ENTITLEMENTS}" \
        "${INNER_SYSTEM_EXTENSION}"

    # A2/B2: sign the bundled signer helper + shim with pinned designated
    # identifiers BEFORE the outer app. The outer app is signed non-deep (below),
    # so these nested signatures are preserved; --deep verify then validates them.
    if [ -x "${SIGNER_HELPER_DST}" ] && [ -x "${SIGNER_CLIENT_DST}" ]; then
        echo "[build-signed]     signing signer helper (${SIGNER_HELPER_ID})"
        codesign \
            --force \
            --options runtime \
            --timestamp \
            --identifier "${SIGNER_HELPER_ID}" \
            --sign "${SIGNING_IDENTITY}" \
            --entitlements "${SIGNER_HELPER_ENTITLEMENTS}" \
            "${SIGNER_HELPER_DST}"
        echo "[build-signed]     signing signer-client shim (${SIGNER_CLIENT_ID})"
        codesign \
            --force \
            --options runtime \
            --timestamp \
            --identifier "${SIGNER_CLIENT_ID}" \
            --sign "${SIGNING_IDENTITY}" \
            --entitlements "${SIGNER_CLIENT_ENTITLEMENTS}" \
            "${SIGNER_CLIENT_DST}"
    else
        echo "[build-signed]     WARN: signer helper/shim not present in bundle; skipping (pre-A2 layout)" >&2
    fi

    BOOT_RUNTIME_NODE="${WRAPPED_APP_DIR}/Contents/Resources/boot-runtime/node"
    BOOT_RUNTIME_DAEMON="${WRAPPED_APP_DIR}/Contents/Resources/boot-runtime/castle-wall-boot-daemon.js"
    if [ -x "${BOOT_RUNTIME_NODE}" ] && [ -f "${BOOT_RUNTIME_DAEMON}" ]; then
        echo "[build-signed]     signing app-bundled Node boot runtime"
        codesign \
            --force \
            --options runtime \
            --timestamp \
            --identifier "ai.sanctuaryprotocol.macos.castle-wall.node" \
            --sign "${SIGNING_IDENTITY}" \
            --entitlements "${BOOT_RUNTIME_NODE_ENTITLEMENTS}" \
            "${BOOT_RUNTIME_NODE}"
    elif [ "${SANCTUARY_REQUIRE_BOOT_RUNTIME:-0}" = "1" ]; then
        echo "[build-signed] ERROR: required app-bundled Castle Wall boot runtime is absent" >&2
        exit 1
    fi

    if [ ! -x "${SANCTUARY_LAUNCHER_DST}" ]; then
        echo "[build-signed] ERROR: required signed-app Sanctuary launcher is absent" >&2
        exit 1
    fi
    echo "[build-signed]     signing sealed Sanctuary launcher (${SANCTUARY_LAUNCHER_ID})"
    codesign \
        --force \
        --options runtime \
        --timestamp \
        --identifier "${SANCTUARY_LAUNCHER_ID}" \
        --sign "${SIGNING_IDENTITY}" \
        "${SANCTUARY_LAUNCHER_DST}"

    echo "[build-signed]     signing every CLI-runtime Mach-O"
    MACH_O_INVENTORY_FILE="$(mktemp "${TMPDIR:-/tmp}/sanctuary-cli-mach-o.XXXXXX")"
    CLI_RUNTIME_MACH_O_COUNT=0
    while IFS= read -r -d '' addon; do
        codesign --force --options runtime --timestamp --sign "${SIGNING_IDENTITY}" "${addon}"
        printf '%s\n' "${addon#${WRAPPED_APP_DIR}/Contents/}" >> "${MACH_O_INVENTORY_FILE}"
        CLI_RUNTIME_MACH_O_COUNT=$((CLI_RUNTIME_MACH_O_COUNT + 1))
    done < <(node "${CLI_RUNTIME_MACH_O_SCANNER}" "${WRAPPED_APP_DIR}/Contents/Resources/cli-runtime")
    if [ "${CLI_RUNTIME_MACH_O_COUNT}" -lt 2 ]; then
        echo "[build-signed] ERROR: expected at least two native Mach-O runtime files" >&2
        exit 1
    fi
    LC_ALL=C sort -o "${MACH_O_INVENTORY_FILE}" "${MACH_O_INVENTORY_FILE}"

    chmod -R a-w "${WRAPPED_APP_DIR}/Contents/Resources/cli-runtime"
    find "${WRAPPED_APP_DIR}/Contents/Resources/cli-runtime" -type d -exec chmod 0555 {} +
    find "${WRAPPED_APP_DIR}/Contents/Resources/cli-runtime" -type f -exec chmod 0444 {} +

    SANCTUARY_MACH_O_INVENTORY_FILE="${MACH_O_INVENTORY_FILE}" \
      node "${REPO_DIR}/server/scripts/build-castle-wall-runtime-manifest.mjs" \
        "${WRAPPED_APP_DIR}" "${CASTLE_WALL_SOURCE_SHA}" "${SANCTUARY_PACKAGE_VERSION}"
    node -e '
      const m = require(process.argv[1]);
      if (m.inventory.file_count > 30000 || m.inventory.total_bytes > 420 * 1024 * 1024) process.exit(1);
      if (m.inventory.mach_o_count < 2 || m.inventory.package_count < 1) process.exit(1);
    ' "${CLI_RUNTIME_MANIFEST}" || {
        echo "[build-signed] ERROR: CLI runtime inventory exceeds its budget or is incomplete" >&2
        exit 1
    }
    rm -f "${MACH_O_INVENTORY_FILE}"
    CLI_RUNTIME_NODE_VERSION="$("${BOOT_RUNTIME_NODE}" --version)"
    CLI_RUNTIME_MANIFEST_SHA256="$(shasum -a 256 "${CLI_RUNTIME_MANIFEST}" | awk '{print $1}')"
    /usr/libexec/PlistBuddy -c "Set :SanctuaryCliRuntimeNodeVersion ${CLI_RUNTIME_NODE_VERSION}" "${WRAPPED_APP_DIR}/Contents/Info.plist" >/dev/null 2>&1 || \
        /usr/libexec/PlistBuddy -c "Add :SanctuaryCliRuntimeNodeVersion string ${CLI_RUNTIME_NODE_VERSION}" "${WRAPPED_APP_DIR}/Contents/Info.plist" >/dev/null
    /usr/libexec/PlistBuddy -c "Set :SanctuaryCliRuntimeManifestSHA256 ${CLI_RUNTIME_MANIFEST_SHA256}" "${WRAPPED_APP_DIR}/Contents/Info.plist" >/dev/null 2>&1 || \
        /usr/libexec/PlistBuddy -c "Add :SanctuaryCliRuntimeManifestSHA256 string ${CLI_RUNTIME_MANIFEST_SHA256}" "${WRAPPED_APP_DIR}/Contents/Info.plist" >/dev/null

    echo "[build-signed]     signing outer .app with Developer ID + host entitlements"
    codesign \
        --force \
        --options runtime \
        --timestamp \
        --sign "${SIGNING_IDENTITY}" \
        --entitlements "${HOST_ENTITLEMENTS}" \
        "${WRAPPED_APP_DIR}"

    echo "[build-signed]     verifying wrapped .app signature"
    codesign --verify --deep --strict "${WRAPPED_APP_DIR}"
    codesign --verify --strict \
        --requirement="anchor apple generic and certificate leaf[subject.OU] = \"YFQSWQ9BJN\" and identifier \"${SANCTUARY_LAUNCHER_ID}\"" \
        "${SANCTUARY_LAUNCHER_DST}"
    VERIFIED_CLI_RUNTIME_MACH_O_COUNT=0
    while IFS= read -r -d '' addon; do
        codesign --verify --strict \
            --requirement='anchor apple generic and certificate leaf[subject.OU] = "YFQSWQ9BJN"' \
            "${addon}"
        VERIFIED_CLI_RUNTIME_MACH_O_COUNT=$((VERIFIED_CLI_RUNTIME_MACH_O_COUNT + 1))
    done < <(node "${CLI_RUNTIME_MACH_O_SCANNER}" "${WRAPPED_APP_DIR}/Contents/Resources/cli-runtime")
    [ "${VERIFIED_CLI_RUNTIME_MACH_O_COUNT}" -eq "${CLI_RUNTIME_MACH_O_COUNT}" ] || {
        echo "[build-signed] ERROR: CLI runtime Mach-O inventory changed after signing" >&2
        exit 1
    }

    # Fail-closed launchability assertions (profile presence at both
    # placements, entitlement coverage, seal integrity). The release workflow
    # runs the same script before notarizing; running it here too means a
    # local wrapped build can never silently produce the v1.7.0/v1.7.1
    # AMFI-dead bundle either.
    echo "[build-signed]     asserting embedded provisioning profiles"
    bash "${PKG_DIR}/scripts/verify-embedded-profiles.sh" "${WRAPPED_APP_DIR}"
    echo "[build-signed] wrapped signed bundle: ${WRAPPED_APP_DIR}"

    # Notarization. An app bundling a LaunchDaemon will leave SMAppService stuck
    # at .requiresApproval/.notFound until the app is notarized + stapled
    # (§9 step 0 precheck). Automate when a notarytool keychain profile is set;
    # otherwise print the exact operator commands.
    if [ -n "${NOTARYTOOL_PROFILE}" ]; then
        echo "[build-signed]     notarizing (profile ${NOTARYTOOL_PROFILE})"
        NOTARIZE_ZIP="${WRAPPED_APP_DIR%.app}-notarize.zip"
        /usr/bin/ditto -c -k --keepParent "${WRAPPED_APP_DIR}" "${NOTARIZE_ZIP}"
        xcrun notarytool submit "${NOTARIZE_ZIP}" \
            --keychain-profile "${NOTARYTOOL_PROFILE}" --wait
        echo "[build-signed]     stapling"
        xcrun stapler staple "${WRAPPED_APP_DIR}"
        xcrun stapler validate "${WRAPPED_APP_DIR}"
        echo "[build-signed]     spctl assess (post-notarization)"
        # Hard gate: a sysext deploy MUST end up notarized-and-accepted, or macOS
        # Tahoe sysextd silently uninstalls the extension at validation (no prompt).
        # Drill 2026-06-11c finding W6-N1.
        if ! spctl -a -vv "${WRAPPED_APP_DIR}" 2>&1 | grep -q "source=Notarized Developer ID"; then
            echo "[build-signed] ERROR: notarization ran but spctl does not report 'Notarized Developer ID' for ${WRAPPED_APP_DIR}." >&2
            echo "[build-signed]        Refusing to emit a sysext bundle that macOS will silently uninstall." >&2
            rm -f "${NOTARIZE_ZIP}"
            exit 1
        fi
        spctl -a -vvv -t exec "${WRAPPED_APP_DIR}" || true
        rm -f "${NOTARIZE_ZIP}"
    elif [ "${ALLOW_UNNOTARIZED}" = true ]; then
        echo "[build-signed]     NOTARIZATION SKIPPED (--allow-unnotarized; NON-DEPLOY build)."
        echo "[build-signed]     WARNING: macOS Tahoe sysextd will REFUSE this extension on a real host." >&2
        echo "[build-signed]     Operator commands to notarize before deploy:"
        echo "[build-signed]       ditto -c -k --keepParent \"${WRAPPED_APP_DIR}\" /tmp/cw-notarize.zip"
        echo "[build-signed]       xcrun notarytool submit /tmp/cw-notarize.zip --keychain-profile <profile> --wait"
        echo "[build-signed]       xcrun stapler staple \"${WRAPPED_APP_DIR}\""
        echo "[build-signed]       xcrun stapler validate \"${WRAPPED_APP_DIR}\""
    else
        echo "[build-signed] ERROR: --wrapped build assembled a .systemextension but NOTARYTOOL_PROFILE is unset." >&2
        echo "[build-signed]        A signed-but-unnotarized system extension is SILENTLY UNINSTALLED by macOS" >&2
        echo "[build-signed]        Tahoe sysextd at validation (no replacement prompt) — the deploy will appear" >&2
        echo "[build-signed]        to succeed and the stale extension stays. (Drill 2026-06-11c, finding W6-N1.)" >&2
        echo "[build-signed]        Fix: set NOTARYTOOL_PROFILE=<notarytool keychain profile> and rebuild," >&2
        echo "[build-signed]        or pass --allow-unnotarized for a CI / local NON-DEPLOY build." >&2
        exit 1
    fi
fi

echo "[build-signed] DONE"
echo "[build-signed] signed bundle: ${BUILD_DIR}"
echo "[build-signed] sha256:"
shasum -a 256 "${BUILD_DIR}/Contents/MacOS/${EXECUTABLE_NAME}"
